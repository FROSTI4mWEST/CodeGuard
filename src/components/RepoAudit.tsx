import React, { useState, useEffect } from 'react';
import { db } from '../lib/firebase';
import { collection, query, orderBy, onSnapshot, doc, updateDoc, serverTimestamp } from 'firebase/firestore';
import { motion, AnimatePresence } from 'motion/react';
import { type Repository, type Scan, type Vulnerability, type VulnerabilityStatus, type VulnerabilitySeverity } from '../types';
import { runSecurityScan } from '../services/vulnerabilityService';
import { auth, handleFirestoreError, OperationType } from '../lib/firebase';
import { createFixPullRequest, commitDirectFix } from '../lib/github';
import { generateJSONReport, generateMarkdownReport, openPrintableReport } from '../utils/reportExporter';
import ReactMarkdown from 'react-markdown';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { Github, Terminal } from 'lucide-react';

function formatScanDate(ts: any): string {
  if (!ts) return 'N/A';
  if (typeof ts === 'string') return new Date(ts).toLocaleString();
  if (ts.seconds) return new Date(ts.seconds * 1000).toLocaleString();
  if (ts.toDate && typeof ts.toDate === 'function') return ts.toDate().toLocaleString();
  return 'N/A';
}

const TechLoader = ({ text }: { text: string }) => (
  <div className="flex flex-col items-center justify-center py-12 space-y-4 font-sans">
    <div className="relative w-16 h-16">
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
        className="absolute inset-0 border-3 border-t-[#1976d2] border-r-transparent border-b-transparent border-l-transparent rounded-full"
      />
      <motion.div
        animate={{ rotate: -360 }}
        transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
        className="absolute inset-2 border-2 border-b-sky-400 border-r-transparent border-t-transparent border-l-transparent rounded-full"
      />
    </div>
    <p className="text-xs font-semibold text-slate-700 animate-pulse uppercase tracking-wider">{text}</p>
  </div>
);

export function RepoAudit({ repoId, onBack }: { repoId: string | null, onBack: () => void }) {
  const [repo, setRepo] = useState<Repository | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [filter, setFilter] = useState<VulnerabilityStatus | 'all'>('all');
  const [severityFilter, setSeverityFilter] = useState<VulnerabilitySeverity | 'all'>('all');
  const [evidenceFilter, setEvidenceFilter] = useState<'all' | 'confirmed' | 'unconfirmed'>('all');
  const [activeTab, setActiveTab] = useState<'findings' | 'timeline' | 'report'>('findings');
  const [selectedScanId, setSelectedScanId] = useState<string | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null);
  const [criticalAlert, setCriticalAlert] = useState<{ show: boolean, count: number }>({ show: false, count: 0 });
  const [scanError, setScanError] = useState<string | null>(null);
  const [showFullHistoryModal, setShowFullHistoryModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);

  useEffect(() => {
    if (!repoId) return;

    const repoRef = doc(db, 'repositories', repoId);
    const unsubRepo = onSnapshot(repoRef, (snap) => {
      if (snap.exists()) {
        setRepo({ id: snap.id, ...snap.data() } as Repository);
      }
    }, (error) => {
      handleFirestoreError(error, OperationType.GET, `repositories/${repoId}`);
    });

    const scansQ = query(
      collection(db, 'repositories', repoId, 'scans'),
      orderBy('createdAt', 'desc')
    );
    const vulnsQ = query(
      collection(db, 'repositories', repoId, 'vulnerabilities'),
      orderBy('severity', 'desc')
    );

    const unsubScans = onSnapshot(scansQ, (snap) => {
      setScans(snap.docs.map(d => ({ id: d.id, ...d.data() } as Scan)));
    }, (error) => {
      handleFirestoreError(error, OperationType.LIST, `repositories/${repoId}/scans`);
    });

    const unsubVulns = onSnapshot(vulnsQ, (snap) => {
      const vulns = snap.docs.map(d => ({ id: d.id, ...d.data() } as Vulnerability));
      setVulnerabilities(vulns);
      
      const criticalCount = vulns.filter(v => v.severity === 'critical' && v.status === 'open').length;
      if (criticalCount > 0 && !scanning) {
        setCriticalAlert({ show: true, count: criticalCount });
      }
      
      setLoading(false);
    }, (error) => {
      handleFirestoreError(error, OperationType.LIST, `repositories/${repoId}/vulnerabilities`);
    });

    return () => {
      unsubRepo();
      unsubScans();
      unsubVulns();
    };
  }, [repoId]);

  const startScan = async () => {
    if (!repo || !auth.currentUser) return;
    setScanning(true);
    setScanError(null);
    try {
      await runSecurityScan(repo, auth.currentUser.uid);
    } catch (error: any) {
      console.error("Security scan error:", error);
      setScanError(error?.message || 'Security scan failed. Detailed logs available in console.');
    } finally {
      setScanning(false);
    }
  };

  const updateVulnStatus = async (vulnId: string, status: VulnerabilityStatus) => {
    if (!repoId) return;
    const path = `repositories/${repoId}/vulnerabilities/${vulnId}`;
    const vulnRef = doc(db, 'repositories', repoId, 'vulnerabilities', vulnId);
    try {
      await updateDoc(vulnRef, { 
        status,
        resolvedAt: status === 'resolved' ? serverTimestamp() : null,
        resolvedBy: status === 'resolved' ? auth.currentUser?.uid : null
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, path);
    }
  };

  const filteredVulns = vulnerabilities.filter(v => {
    const matchesStatus = filter === 'all' || v.status === filter;
    const matchesSeverity = severityFilter === 'all' || v.severity === severityFilter;
    const matchesEvidence = evidenceFilter === 'all' || 
      (evidenceFilter === 'confirmed' && (v.evidenceStatus === 'CONFIRMED' || v.verified)) ||
      (evidenceFilter === 'unconfirmed' && (v.evidenceStatus === 'UNCONFIRMED' || !v.verified));
    const matchesScan = selectedScanId === 'all' || v.scanId === selectedScanId;
    const matchesSearch = !searchQuery || 
      v.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
      v.filePath.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (v.codeEvidence && v.codeEvidence.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesStatus && matchesSeverity && matchesEvidence && matchesScan && matchesSearch;
  });

  const severityData = [
    { name: 'CRITICAL', count: vulnerabilities.filter(v => v.severity === 'critical').length, color: '#ff3344', key: 'critical' },
    { name: 'HIGH', count: vulnerabilities.filter(v => v.severity === 'high').length, color: '#ffcc00', key: 'high' },
    { name: 'MEDIUM', count: vulnerabilities.filter(v => v.severity === 'medium').length, color: '#00b4d8', key: 'medium' },
    { name: 'LOW', count: vulnerabilities.filter(v => v.severity === 'low').length, color: '#0077b6', key: 'low' },
  ];

  // Combine scans and vulnerabilities into a visual chronological audit timeline
  const timelineEvents = [
    ...scans.map(s => ({
      id: `scan-${s.id}`,
      type: 'scan' as const,
      date: s.createdAt,
      title: `AUTOMATED AUDIT RUN #${s.id.substring(0, 6)}`,
      subtitle: `Health Score: ${s.score ?? '--'}% • ${s.findingsCount ?? 0} Findings Detected`,
      status: s.status,
      badgeColor: s.status === 'completed' ? '#00b4d8' : '#ffcc00',
      data: s
    })),
    ...vulnerabilities.map(v => ({
      id: `vuln-${v.id}`,
      type: 'vulnerability' as const,
      date: v.detectedAt,
      title: `Vulnerability Discovered: ${v.title}`,
      subtitle: `File: ${v.filePath} • Category: ${v.category}`,
      severity: v.severity,
      status: v.status,
      badgeColor: v.severity === 'critical' ? '#ff3344' : v.severity === 'high' ? '#ffcc00' : v.severity === 'medium' ? '#00b4d8' : '#0077b6',
      data: v
    }))
  ].sort((a, b) => {
    const parseDate = (d: any) => {
      if (!d) return 0;
      if (typeof d === 'string') return new Date(d).getTime();
      if (d && typeof d === 'object' && 'seconds' in d) return d.seconds * 1000;
      return new Date(d).getTime();
    };
    return parseDate(b.date) - parseDate(a.date);
  });

  if (!repoId || !repo) {
    return (
      <div className="h-[60vh] flex items-center justify-center font-sans">
        <TechLoader text="ANALYZING REPOSITORY SECURITY PERIMETER..." />
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      className="max-w-6xl mx-auto space-y-6 pb-12 font-sans"
    >
      <AnimatePresence>
        {criticalAlert.show && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="border border-red-200 bg-red-50 rounded-xl p-4 flex items-center justify-between shadow-xs"
          >
            <div>
              <p className="text-red-700 font-bold text-xs uppercase tracking-wider">CRITICAL VULNERABILITIES DETECTED</p>
              <p className="text-red-600/90 text-xs mt-0.5">Found {criticalAlert.count} critical findings requiring immediate remediation.</p>
            </div>
            <button 
              onClick={() => setCriticalAlert({ ...criticalAlert, show: false })}
              className="text-red-500 hover:text-red-700 transition-colors font-bold text-xs px-2 py-1 cursor-pointer"
            >
              CLOSE
            </button>
          </motion.div>
        )}

        {scanError && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="border border-red-200 bg-red-50 rounded-xl p-4 flex items-center justify-between shadow-xs"
          >
            <div>
              <p className="text-red-700 font-bold text-xs uppercase tracking-wider">SECURITY SCAN NOTICE</p>
              <p className="text-red-600/90 text-xs mt-0.5">{scanError}</p>
            </div>
            <button 
              onClick={() => setScanError(null)}
              className="text-red-500 hover:text-red-700 transition-colors font-bold text-xs px-2 py-1 cursor-pointer"
            >
              CLOSE
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Header with Navigation & Tab Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <button onClick={onBack} className="github-btn-secondary text-xs cursor-pointer font-semibold">
          BACK TO REPOSITORIES
        </button>

        {/* View Tabs Switcher */}
        <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl border border-slate-200">
          <button
            onClick={() => setActiveTab('findings')}
            className={`px-3.5 py-1.5 text-xs font-bold uppercase rounded-lg transition-colors cursor-pointer ${
              activeTab === 'findings' ? 'bg-white text-[#1976d2] shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            FINDINGS ({filteredVulns.length})
          </button>
          <button
            onClick={() => setActiveTab('timeline')}
            className={`px-3.5 py-1.5 text-xs font-bold uppercase rounded-lg transition-colors cursor-pointer ${
              activeTab === 'timeline' ? 'bg-white text-[#1976d2] shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            AUDIT TIMELINE
          </button>
          <button
            onClick={() => setActiveTab('report')}
            className={`px-3.5 py-1.5 text-xs font-bold uppercase rounded-lg transition-colors cursor-pointer ${
              activeTab === 'report' ? 'bg-white text-[#1976d2] shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            REPORT & COMPLIANCE
          </button>
        </div>

        <div className="flex items-center gap-2">
          <button 
            onClick={() => setShowExportModal(true)}
            className="github-btn-secondary text-xs cursor-pointer font-semibold"
          >
            EXPORT REPORT
          </button>
          <button 
            onClick={startScan}
            disabled={scanning}
            className="github-btn-primary text-xs cursor-pointer font-semibold"
          >
            {scanning ? 'RUNNING AUDIT...' : 'RE-SCAN ASSET'}
          </button>
        </div>
      </div>

      <AnimatePresence>
        {scanning && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="border border-blue-200 bg-white rounded-xl p-8 mb-6 shadow-sm"
          >
            <TechLoader text="SECURITY AUDIT IN PROGRESS • MATCHING OWASP BENCHMARKS..." />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Repo Stats Bar */}
      <div className="border border-slate-200 bg-white rounded-xl p-6 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2.5 text-slate-900 uppercase">
            <Github className="w-5 h-5 text-slate-700 shrink-0" />
            <span>{repo.full_name}</span>
            {repo.visibility === 'private' && (
              <span className="text-[10px] bg-[#8D4F27] text-white px-2 py-0.5 rounded font-bold">PRIVATE</span>
            )}
          </h1>
          <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
            <span className="text-[#1976d2] font-semibold">SECURITY AUDIT ACTIVE</span>
            <span>•</span>
            <span>{scans.length} TOTAL SCANS</span>
          </div>
        </div>

        <div className="flex items-center gap-8">
          <div className="text-center">
            <div className="text-[10px] text-slate-500 font-bold uppercase mb-1">HEALTH SCORE</div>
            <div className={`text-3xl font-bold ${getHealthScoreColor(repo.healthScore || 0)}`}>
              {repo.healthScore || '--'}%
            </div>
          </div>
        </div>
      </div>

      {/* TAB 1: FINDINGS AUDIT VIEW */}
      {activeTab === 'findings' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Visuals & Scanning history */}
          <div className="space-y-6">
            <div className="border border-slate-200 bg-white rounded-xl p-4 shadow-xs">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-bold text-slate-800 uppercase">
                  SEVERITY DISTRIBUTION
                </h3>
                <span className="text-[11px] text-slate-500">Click bar to filter</span>
              </div>
              <div className="h-44 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                    <XAxis dataKey="name" axisLine={{ stroke: '#cbd5e1' }} tickLine={false} tick={{ fill: '#64748b', fontSize: 11 }} />
                    <YAxis axisLine={{ stroke: '#cbd5e1' }} tickLine={false} tick={{ fill: '#64748b', fontSize: 11 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #cbd5e1', color: '#1e293b', borderRadius: '8px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {severityData.map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`} 
                          fill={entry.color} 
                          className="cursor-pointer hover:opacity-80 transition-opacity"
                          onClick={() => setSeverityFilter(severityFilter === entry.key ? 'all' : entry.key as any)}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="border border-slate-200 bg-white rounded-xl shadow-xs overflow-hidden">
              <div className="p-3 border-b border-slate-200 bg-[#f8fafc] flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-800 uppercase">
                  REPO SCAN HISTORY ({scans.length})
                </h3>
                {selectedScanId !== 'all' && (
                  <button 
                    onClick={() => setSelectedScanId('all')} 
                    className="text-[11px] text-[#1976d2] font-semibold hover:underline cursor-pointer"
                  >
                    SHOW ALL
                  </button>
                )}
              </div>
              
              <div className="divide-y divide-slate-100 max-h-72 overflow-y-auto">
                <div 
                  onClick={() => setSelectedScanId('all')}
                  className={`p-3 cursor-pointer transition-colors flex items-center justify-between ${selectedScanId === 'all' ? 'bg-blue-50/60 font-bold text-[#1976d2]' : 'hover:bg-slate-50'}`}
                >
                  <span className="text-xs">ALL HISTORICAL SCANS</span>
                  <span className="text-[11px] text-slate-500">{vulnerabilities.length} TOTAL FINDINGS</span>
                </div>

                {scans.length === 0 ? (
                  <div className="p-4 text-center text-slate-400 text-xs">NO SCAN HISTORY RECORDED YET</div>
                ) : (
                  scans.map(scan => (
                    <div 
                      key={scan.id} 
                      onClick={() => setSelectedScanId(scan.id)}
                      className={`p-3 cursor-pointer transition-colors ${selectedScanId === scan.id ? 'bg-blue-50 border-l-3 border-[#1976d2]' : 'hover:bg-slate-50'}`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-slate-800">{formatScanDate(scan.createdAt)}</span>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${scan.status === 'completed' ? 'bg-blue-50 text-[#1976d2] border border-blue-200' : 'bg-amber-50 text-amber-600 border border-amber-200'}`}>
                          {scan.status?.toUpperCase() || 'COMPLETED'}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-[11px] text-slate-500">
                        <span>{scan.findingsCount ?? 0} FINDINGS</span>
                        <span>SCORE: {scan.score ?? '--'}%</span>
                      </div>
                    </div>
                  ))
                )}
              </div>

              {scans.length > 0 && (
                <div className="p-2 border-t border-slate-200 bg-[#f8fafc]">
                  <button 
                    onClick={() => setShowFullHistoryModal(true)}
                    className="w-full github-btn-secondary text-[11px] py-1.5 flex items-center justify-center cursor-pointer font-semibold"
                  >
                    VIEW FULL SCAN AUDIT LOGS
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Right Column: Findings */}
          <div className="lg:col-span-2 space-y-4">
            {/* Search + Filters */}
            <div className="space-y-3 bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
              <div>
                <input 
                  type="text" 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search vulnerabilities by title, file, or category..."
                  className="w-full bg-[#f8fafc] border border-slate-200 rounded-lg px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-[#1976d2] focus:bg-white transition-all font-sans"
                />
              </div>

              {/* Severity Filter Pills */}
              <div className="flex items-center gap-1.5 flex-wrap pt-2 border-t border-slate-100">
                <span className="text-[11px] text-slate-500 font-bold uppercase mr-1">SEVERITY:</span>
                <FilterButton active={severityFilter === 'all'} onClick={() => setSeverityFilter('all')}>
                  ALL ({vulnerabilities.length})
                </FilterButton>
                <FilterButton active={severityFilter === 'critical'} onClick={() => setSeverityFilter(severityFilter === 'critical' ? 'all' : 'critical')}>
                  <span className="text-red-600">CRITICAL ({vulnerabilities.filter(v => v.severity === 'critical').length})</span>
                </FilterButton>
                <FilterButton active={severityFilter === 'high'} onClick={() => setSeverityFilter(severityFilter === 'high' ? 'all' : 'high')}>
                  <span className="text-amber-600">HIGH ({vulnerabilities.filter(v => v.severity === 'high').length})</span>
                </FilterButton>
                <FilterButton active={severityFilter === 'medium'} onClick={() => setSeverityFilter(severityFilter === 'medium' ? 'all' : 'medium')}>
                  <span className="text-blue-600">MEDIUM ({vulnerabilities.filter(v => v.severity === 'medium').length})</span>
                </FilterButton>
                <FilterButton active={severityFilter === 'low'} onClick={() => setSeverityFilter(severityFilter === 'low' ? 'all' : 'low')}>
                  <span className="text-slate-600">LOW ({vulnerabilities.filter(v => v.severity === 'low').length})</span>
                </FilterButton>
              </div>

              {/* Status Filter Pills */}
              <div className="flex items-center gap-1.5 flex-wrap pt-2 border-t border-slate-100">
                <span className="text-[11px] text-slate-500 font-bold uppercase mr-1">STATUS:</span>
                <FilterButton active={filter === 'all'} onClick={() => setFilter('all')}>ALL</FilterButton>
                <FilterButton active={filter === 'open'} onClick={() => setFilter('open')}>OPEN</FilterButton>
                <FilterButton active={filter === 'in-progress'} onClick={() => setFilter('in-progress')}>ACTIVE</FilterButton>
                <FilterButton active={filter === 'resolved'} onClick={() => setFilter('resolved')}>FIXED</FilterButton>
              </div>

              {/* Evidence Verification Filter Pills */}
              <div className="flex items-center gap-1.5 flex-wrap pt-2 border-t border-slate-100">
                <span className="text-[11px] text-slate-500 font-bold uppercase mr-1">EVIDENCE:</span>
                <FilterButton active={evidenceFilter === 'all'} onClick={() => setEvidenceFilter('all')}>
                  ALL ({vulnerabilities.length})
                </FilterButton>
                <FilterButton active={evidenceFilter === 'confirmed'} onClick={() => setEvidenceFilter(evidenceFilter === 'confirmed' ? 'all' : 'confirmed')}>
                  <span className="text-emerald-700">
                    CONFIRMED ({vulnerabilities.filter(v => v.evidenceStatus === 'CONFIRMED' || v.verified).length})
                  </span>
                </FilterButton>
                <FilterButton active={evidenceFilter === 'unconfirmed'} onClick={() => setEvidenceFilter(evidenceFilter === 'unconfirmed' ? 'all' : 'unconfirmed')}>
                  <span className="text-amber-600">
                    UNCONFIRMED ({vulnerabilities.filter(v => v.evidenceStatus === 'UNCONFIRMED' || !v.verified).length})
                  </span>
                </FilterButton>
              </div>
            </div>

            {(selectedScanId !== 'all' || severityFilter !== 'all') && (
              <div className="p-2.5 rounded-lg border border-blue-200 bg-blue-50 flex items-center justify-between text-xs text-[#1976d2]">
                <span className="flex items-center gap-2">
                  ACTIVE FILTERS: 
                  {selectedScanId !== 'all' && <span className="font-bold">SCAN: {scans.find(s => s.id === selectedScanId) ? formatScanDate(scans.find(s => s.id === selectedScanId)?.createdAt) : selectedScanId}</span>}
                  {severityFilter !== 'all' && <span className="font-bold uppercase">SEVERITY: {severityFilter}</span>}
                </span>
                <button 
                  onClick={() => { setSelectedScanId('all'); setSeverityFilter('all'); }} 
                  className="text-[#1976d2] hover:underline text-xs font-semibold cursor-pointer"
                >
                  CLEAR FILTERS
                </button>
              </div>
            )}

            <div className="space-y-3">
              {loading ? (
                <div className="border border-slate-200 bg-white rounded-xl p-8 text-center text-slate-500 text-xs shadow-xs">
                  EVALUATING SECURITY FINDINGS...
                </div>
              ) : filteredVulns.length === 0 ? (
                <div className="border border-slate-200 bg-white rounded-xl p-8 text-center border-dashed shadow-xs">
                  <p className="text-slate-700 text-xs font-bold uppercase">NO VULNERABILITIES MATCH CURRENT FILTERS</p>
                </div>
              ) : (
                filteredVulns.map(vuln => (
                  <VulnerabilityCard 
                    key={vuln.id} 
                    vuln={vuln} 
                    expanded={selectedVulnId === vuln.id}
                    onToggle={() => setSelectedVulnId(selectedVulnId === vuln.id ? null : vuln.id)}
                    onStatusUpdate={(status) => updateVulnStatus(vuln.id, status)}
                    owner={repo.owner}
                    repoName={repo.name}
                  />
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: INTERACTIVE AUDIT TIMELINE VIEW */}
      {activeTab === 'timeline' && (
        <div className="border border-slate-200 bg-white rounded-xl p-6 shadow-xs space-y-6">
          <div className="flex items-center justify-between border-b border-slate-200 pb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-800 uppercase">
                CHRONOLOGICAL AUDIT TIMELINE
              </h3>
              <p className="text-xs text-slate-500 mt-1">
                Complete security lifecycle events including scans, vulnerability discoveries, and remediation pull requests.
              </p>
            </div>
            <span className="text-xs text-[#1976d2] font-semibold bg-blue-50 border border-blue-200 px-3 py-1 rounded-full">
              {timelineEvents.length} TOTAL EVENTS
            </span>
          </div>

          <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
            {timelineEvents.length === 0 ? (
              <p className="text-xs text-slate-500 py-8 text-center">NO AUDIT TIMELINE EVENTS RECORDED</p>
            ) : (
              timelineEvents.map((event) => (
                <div key={event.id} className="relative group">
                  {/* Timeline Node Icon */}
                  <div 
                    className="absolute -left-[27px] top-1 w-4 h-4 rounded-full border-2 bg-white flex items-center justify-center shadow-xs"
                    style={{ borderColor: event.badgeColor }}
                  >
                    <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: event.badgeColor }} />
                  </div>

                  {/* Event Box */}
                  <div className="border border-slate-200 bg-[#f8fafc] rounded-xl p-4 hover:border-slate-300 transition-colors space-y-2">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 pb-2">
                      <div className="flex items-center gap-2">
                        <span 
                          className="text-[10px] font-bold px-2 py-0.5 uppercase rounded-md border"
                          style={{ borderColor: event.badgeColor, color: event.badgeColor, backgroundColor: `${event.badgeColor}15` }}
                        >
                          {event.type.toUpperCase()}
                        </span>
                        <h4 className="font-bold text-xs text-slate-800">{event.title}</h4>
                      </div>
                      <span className="text-[11px] text-slate-500 font-mono">
                        {formatScanDate(event.date)}
                      </span>
                    </div>

                    <p className="text-xs text-slate-600">{event.subtitle}</p>

                    {/* Sub-details depending on event type */}
                    {event.type === 'vulnerability' && (
                      <div className="flex items-center justify-between pt-2 border-t border-slate-200 text-xs">
                        <span className="text-slate-500 font-mono">STATUS: {event.status?.toUpperCase()}</span>
                        <button
                          onClick={() => {
                            setActiveTab('findings');
                            setSelectedVulnId((event.data as Vulnerability).id);
                          }}
                          className="text-[#1976d2] hover:underline uppercase font-bold cursor-pointer"
                        >
                          INSPECT FINDING &rarr;
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 3: REPORT & COMPLIANCE CENTER VIEW */}
      {activeTab === 'report' && (
        <div className="border border-slate-200 bg-white rounded-xl p-6 shadow-xs space-y-6">
          <div className="flex items-center justify-between border-b border-slate-200 pb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-800 uppercase">
                COMPLIANCE & SECURITY AUDIT REPORT
              </h3>
              <p className="text-xs text-slate-500 mt-1">
                Generated executive compliance report for asset <span className="text-slate-800 font-bold">{repo.full_name}</span>.
              </p>
            </div>
            <button 
              onClick={() => openPrintableReport(repo, scans, vulnerabilities)}
              className="github-btn-primary text-xs cursor-pointer font-semibold"
            >
              PRINT / PDF REPORT
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="border border-slate-200 bg-[#f8fafc] rounded-xl p-4 text-center">
              <div className="text-[10px] text-slate-500 uppercase font-bold">HEALTH SCORE</div>
              <div className={`text-2xl font-bold mt-1 ${getHealthScoreColor(repo.healthScore ?? 0)}`}>
                {repo.healthScore ?? 100}%
              </div>
            </div>
            <div className="border border-slate-200 bg-[#f8fafc] rounded-xl p-4 text-center">
              <div className="text-[10px] text-slate-500 uppercase font-bold">TOTAL SCANS</div>
              <div className="text-2xl font-bold text-slate-800 mt-1">{scans.length}</div>
            </div>
            <div className="border border-slate-200 bg-[#f8fafc] rounded-xl p-4 text-center">
              <div className="text-[10px] text-slate-500 uppercase font-bold">CRITICAL FINDINGS</div>
              <div className="text-2xl font-bold text-red-600 mt-1">
                {vulnerabilities.filter(v => v.severity === 'critical').length}
              </div>
            </div>
            <div className="border border-slate-200 bg-[#f8fafc] rounded-xl p-4 text-center">
              <div className="text-[10px] text-slate-500 uppercase font-bold">RESOLVED ISSUES</div>
              <div className="text-2xl font-bold text-[#1976d2] mt-1">
                {vulnerabilities.filter(v => v.status === 'resolved').length}
              </div>
            </div>
          </div>

          {/* Export Action Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4 border-t border-slate-200">
            <div className="border border-slate-200 bg-[#f8fafc] rounded-xl p-4 space-y-3">
              <h4 className="font-bold text-xs text-slate-800 uppercase">
                EXPORT JSON DATA
              </h4>
              <p className="text-xs text-slate-500 leading-relaxed">
                Download structured JSON report containing raw findings, scan records, and vulnerability metrics.
              </p>
              <button
                onClick={() => generateJSONReport(repo, scans, vulnerabilities)}
                className="w-full github-btn-secondary text-xs py-2 cursor-pointer font-semibold"
              >
                DOWNLOAD JSON
              </button>
            </div>

            <div className="border border-slate-200 bg-[#f8fafc] rounded-xl p-4 space-y-3">
              <h4 className="font-bold text-xs text-slate-800 uppercase">
                EXPORT MARKDOWN
              </h4>
              <p className="text-xs text-slate-500 leading-relaxed">
                Download formatted Markdown security documentation suitable for GitHub repository READMEs.
              </p>
              <button
                onClick={() => generateMarkdownReport(repo, scans, vulnerabilities)}
                className="w-full github-btn-secondary text-xs py-2 cursor-pointer font-semibold"
              >
                DOWNLOAD MARKDOWN
              </button>
            </div>

            <div className="border border-slate-200 bg-[#f8fafc] rounded-xl p-4 space-y-3">
              <h4 className="font-bold text-xs text-slate-800 uppercase">
                PRINT / PDF REPORT
              </h4>
              <p className="text-xs text-slate-500 leading-relaxed">
                Generate print-formatted HTML audit summary ready for browser print or PDF saving.
              </p>
              <button
                onClick={() => openPrintableReport(repo, scans, vulnerabilities)}
                className="w-full github-btn-primary text-xs py-2 cursor-pointer font-semibold"
              >
                GENERATE PRINTABLE
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Export Report Popup Modal */}
      <AnimatePresence>
        {showExportModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 font-sans">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-slate-900/60 backdrop-blur-xs"
              onClick={() => setShowExportModal(false)}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="relative bg-white border border-slate-200 rounded-2xl w-full max-w-lg p-0 shadow-2xl overflow-hidden text-slate-800"
            >
              <div className="px-6 py-4 border-b border-slate-100 bg-[#f8fafc] flex items-center justify-between">
                <div>
                  <h3 className="font-bold text-slate-900 uppercase text-sm">
                    EXPORT SECURITY AUDIT REPORT
                  </h3>
                </div>
                <button 
                  onClick={() => setShowExportModal(false)}
                  className="text-slate-400 hover:text-slate-700 p-1 cursor-pointer rounded-lg hover:bg-slate-100 transition-colors text-xs font-bold"
                >
                  CLOSE
                </button>
              </div>

              <div className="p-6 space-y-4">
                <p className="text-xs text-slate-500">
                  Select preferred export format for security report of repository <span className="text-slate-800 font-bold">{repo.full_name}</span>.
                </p>

                <div className="space-y-3">
                  <button
                    onClick={() => { generateJSONReport(repo, scans, vulnerabilities); setShowExportModal(false); }}
                    className="w-full p-3.5 border border-slate-200 hover:border-blue-400 bg-white hover:bg-blue-50/50 rounded-xl text-left flex items-center justify-between transition-all cursor-pointer shadow-xs"
                  >
                    <div>
                      <div className="font-bold text-xs text-slate-800">JSON FORMAT (.json)</div>
                      <p className="text-[11px] text-slate-500">Structured data payload containing full findings & metrics</p>
                    </div>
                    <span className="text-xs font-bold text-[#1976d2]">DOWNLOAD</span>
                  </button>

                  <button
                    onClick={() => { generateMarkdownReport(repo, scans, vulnerabilities); setShowExportModal(false); }}
                    className="w-full p-3.5 border border-slate-200 hover:border-blue-400 bg-white hover:bg-blue-50/50 rounded-xl text-left flex items-center justify-between transition-all cursor-pointer shadow-xs"
                  >
                    <div>
                      <div className="font-bold text-xs text-slate-800">MARKDOWN FORMAT (.md)</div>
                      <p className="text-[11px] text-slate-500">Formatted documentation suitable for GitHub READMEs</p>
                    </div>
                    <span className="text-xs font-bold text-[#1976d2]">DOWNLOAD</span>
                  </button>

                  <button
                    onClick={() => { openPrintableReport(repo, scans, vulnerabilities); setShowExportModal(false); }}
                    className="w-full p-3.5 border border-blue-200 bg-blue-50/50 hover:bg-blue-100/50 rounded-xl text-left flex items-center justify-between transition-all cursor-pointer shadow-xs"
                  >
                    <div>
                      <div className="font-bold text-xs text-[#1976d2]">PRINTABLE PDF / SUMMARY</div>
                      <p className="text-[11px] text-slate-600">Print-optimized HTML report ready for PDF export</p>
                    </div>
                    <span className="text-xs font-bold text-[#1976d2]">OPEN</span>
                  </button>
                </div>
              </div>

              <div className="px-6 py-3 border-t border-slate-100 bg-[#f8fafc] flex justify-end">
                <button
                  onClick={() => setShowExportModal(false)}
                  className="github-btn-secondary text-xs cursor-pointer font-semibold"
                >
                  CLOSE
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Full Scan Audit History Modal */}
      <AnimatePresence>
        {showFullHistoryModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 font-sans">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-slate-900/60 backdrop-blur-xs" 
              onClick={() => setShowFullHistoryModal(false)}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="relative bg-white border border-slate-200 rounded-2xl w-full max-w-3xl max-h-[85vh] flex flex-col p-0 shadow-2xl overflow-hidden font-sans"
            >
              <div className="px-6 py-4 border-b border-slate-100 bg-[#f8fafc] flex items-center justify-between">
                <div>
                  <h3 className="font-bold text-slate-900 uppercase text-sm">
                    COMPLETE SCAN HISTORY AUDIT LOGS ({scans.length})
                  </h3>
                </div>
                <button 
                  onClick={() => setShowFullHistoryModal(false)} 
                  className="text-slate-400 hover:text-slate-700 p-1 cursor-pointer rounded-lg hover:bg-slate-100 transition-colors text-xs font-bold"
                >
                  CLOSE
                </button>
              </div>

              <div className="p-6 overflow-y-auto flex-1 space-y-4">
                <p className="text-slate-500 text-xs">
                  Historical security scan audits executed on repository <span className="text-slate-800 font-bold">{repo.full_name}</span>. Click any scan to filter the main audit view.
                </p>

                <div className="border border-slate-200 rounded-xl bg-white divide-y divide-slate-100 overflow-hidden shadow-xs">
                  {scans.length === 0 ? (
                    <div className="p-8 text-center text-slate-500 text-xs">NO HISTORICAL SCANS RECORDED</div>
                  ) : (
                    scans.map((scan, idx) => (
                      <div key={scan.id} className="p-4 hover:bg-slate-50 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                        <div className="space-y-1">
                          <div className="flex items-center gap-3">
                            <span className="text-xs font-bold text-slate-800">
                              SCAN #{scans.length - idx} • {scan.id.substring(0, 8)}
                            </span>
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${scan.status === 'completed' ? 'border-emerald-200 text-emerald-700 bg-emerald-50' : 'border-amber-200 text-amber-700 bg-amber-50'}`}>
                              {scan.status?.toUpperCase() || 'COMPLETED'}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500 font-mono">
                            EXECUTED: {formatScanDate(scan.createdAt)}
                          </div>
                          <div className="flex items-center gap-2 text-[11px] text-slate-600 pt-1 font-mono">
                            <span className="text-red-600 font-semibold">CRITICAL: {scan.criticalCount ?? 0}</span> • 
                            <span className="text-amber-600 font-semibold">HIGH: {scan.highCount ?? 0}</span> • 
                            <span className="text-blue-600 font-semibold">MEDIUM: {scan.mediumCount ?? 0}</span> • 
                            <span className="text-slate-600 font-semibold">LOW: {scan.lowCount ?? 0}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-4">
                          <div className="text-right">
                            <div className="text-[10px] text-slate-400 uppercase font-bold">SCORE</div>
                            <div className={`text-xl font-bold ${getHealthScoreColor(scan.score ?? 0)}`}>
                              {scan.score ?? '--'}%
                            </div>
                          </div>
                          <button
                            onClick={() => {
                              setSelectedScanId(scan.id);
                              setShowFullHistoryModal(false);
                            }}
                            className="github-btn-primary text-xs py-1.5 px-3 cursor-pointer font-semibold"
                          >
                            INSPECT FINDINGS
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="px-6 py-3 border-t border-slate-100 bg-[#f8fafc] flex justify-end">
                <button 
                  onClick={() => setShowFullHistoryModal(false)} 
                  className="github-btn-secondary text-xs cursor-pointer font-semibold"
                >
                  CLOSE
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function FilterButton({ active, children, onClick }: { active: boolean, children: React.ReactNode, onClick: () => void }) {
  return (
    <button 
      onClick={onClick}
      className={`px-3 py-1 text-[11px] font-bold uppercase tracking-wider rounded-lg transition-all whitespace-nowrap border cursor-pointer ${
        active 
          ? 'bg-[#1976d2] text-white border-[#1976d2] shadow-xs' 
          : 'bg-[#f8fafc] text-slate-600 border-slate-200 hover:text-[#1976d2] hover:border-blue-300 hover:bg-blue-50/50'
      }`}
    >
      {children}
    </button>
  );
}

interface VulnerabilityCardProps {
  vuln: Vulnerability;
  expanded: boolean;
  onToggle: () => void;
  onStatusUpdate: (s: VulnerabilityStatus) => void;
  owner: string;
  repoName: string;
}

function VulnerabilityCard({ vuln, expanded, onToggle, onStatusUpdate, owner, repoName }: VulnerabilityCardProps) {
  const [pushingMode, setPushingMode] = useState<'commit' | 'pr' | null>(null);
  const [fixSuccess, setFixSuccess] = useState<{ type: 'commit' | 'pr'; url: string; branch?: string; isSandbox?: boolean } | null>(null);
  const [pushError, setPushError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handlePushDirectFix = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setPushingMode('commit');
    setPushError(null);
    try {
      const result = await commitDirectFix(
        owner,
        repoName,
        vuln.filePath,
        vuln.fix || vuln.remediation,
        vuln.title,
        vuln.codeEvidence || vuln.codeSnippet
      );
      setFixSuccess({ type: 'commit', url: result.url, branch: result.branch, isSandbox: result.isSandbox });
      onStatusUpdate('resolved');
    } catch (err: any) {
      console.error("Direct commit error:", err);
      setPushError(err.message || 'Failed to update code on GitHub. Ensure your GitHub account has write access to this repo.');
    } finally {
      setPushingMode(null);
    }
  };

  const handlePushPR = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setPushingMode('pr');
    setPushError(null);
    try {
      const pr = await createFixPullRequest(
        owner,
        repoName,
        vuln.filePath,
        vuln.fix || vuln.remediation,
        vuln.title,
        vuln.codeEvidence || vuln.codeSnippet,
        vuln.impact || vuln.explanation
      );
      setFixSuccess({ type: 'pr', url: pr.html_url, branch: pr.branch, isSandbox: pr.isSandbox });
      onStatusUpdate('in-progress');
    } catch (err: any) {
      console.error("PR creation error:", err);
      setPushError(err.message || 'Failed to create PR. Ensure your GitHub account has repository permissions.');
    } finally {
      setPushingMode(null);
    }
  };

  const handleCopyFix = (e: React.MouseEvent) => {
    e.stopPropagation();
    const fixCode = vuln.fix || vuln.remediation || '';
    navigator.clipboard.writeText(fixCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isConfirmed = vuln.evidenceStatus === 'CONFIRMED' || vuln.verified;

  const getSeverityStyle = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'border-red-200 text-red-700 bg-red-50';
      case 'high': return 'border-amber-200 text-amber-700 bg-amber-50';
      case 'medium': return 'border-blue-200 text-[#1976d2] bg-blue-50';
      default: return 'border-slate-200 text-slate-700 bg-slate-100';
    }
  };

  const lineNum = vuln.lineNumber || vuln.lineStart;
  const attackText = vuln.impact || vuln.risk || '';

  return (
    <div className={`border rounded-xl bg-white shadow-xs overflow-hidden transition-all duration-200 ${isConfirmed ? 'border-slate-200 hover:border-blue-300 hover:shadow-sm' : 'border-amber-200'}`}>
      <div 
        onClick={onToggle}
        className="p-4 flex items-center gap-4 cursor-pointer hover:bg-slate-50/70 select-none transition-colors"
      >
        <div className={`shrink-0 w-1.5 h-10 rounded-full ${vuln.severity === 'critical' ? 'bg-red-500' : isConfirmed ? 'bg-[#1976d2]' : 'bg-amber-500'}`} />
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            <span className={`text-[10px] px-2 py-0.5 border rounded-md font-bold uppercase tracking-wider ${getSeverityStyle(vuln.severity)}`}>
              {vuln.severity} RISK
            </span>

            <span className={`text-[10px] px-2 py-0.5 border rounded-md font-bold uppercase ${isConfirmed ? 'border-emerald-200 text-emerald-700 bg-emerald-50' : 'border-amber-200 text-amber-700 bg-amber-50'}`}>
              {isConfirmed ? 'CONFIRMED IN CODE' : 'SUSPECTED'}
            </span>

            <span className="text-[11px] text-slate-600 font-mono bg-slate-100 px-2 py-0.5 rounded-md border border-slate-200 truncate max-w-[280px]">
              {vuln.filePath}{lineNum ? ` : line ${lineNum}` : ''}
            </span>

            {vuln.ruleId && (
              <span className="text-[10px] text-slate-500 font-mono px-1.5 py-0.5 bg-slate-100 rounded border border-slate-200">
                {vuln.ruleId}
              </span>
            )}
          </div>
          
          <h4 className="text-sm font-bold text-slate-900 tracking-tight truncate">
            {vuln.title}
          </h4>
        </div>

        <div className="flex items-center gap-3">
          <span className={`text-[10px] px-2.5 py-1 border rounded-full font-bold uppercase ${vuln.status === 'resolved' ? 'border-emerald-200 text-emerald-700 bg-emerald-50' : 'border-slate-200 text-slate-600 bg-slate-50'}`}>
            {vuln.status === 'resolved' ? 'RESOLVED' : vuln.status}
          </span>
          <span className="text-xs text-slate-400 font-bold uppercase">
            {expanded ? 'HIDE' : 'VIEW'}
          </span>
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-slate-100 bg-[#f8fafc]"
          >
            <div className="p-5 space-y-5">
              {/* Vulnerability Explanation */}
              <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2 shadow-xs">
                <h5 className="text-xs font-bold text-[#1976d2] uppercase tracking-wide">
                  WHAT IS THIS ISSUE?
                </h5>
                <p className="text-xs text-slate-700 leading-relaxed font-sans">
                  {vuln.explanation || vuln.description}
                </p>
              </div>

              {/* The Attack Story / Scenario */}
              <div className="bg-red-50/50 border border-red-200 rounded-xl p-4 space-y-2">
                <h5 className="text-xs font-bold text-red-600 uppercase tracking-wide">
                  ATTACK SCENARIO & EXPLOITATION PATH
                </h5>
                <div className="text-xs text-slate-700 leading-relaxed space-y-2 font-sans">
                  <ReactMarkdown>{attackText}</ReactMarkdown>
                </div>
              </div>

              {/* Code Evidence Section */}
              {(vuln.codeEvidence || vuln.codeSnippet) && (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <h5 className="text-[11px] font-bold text-slate-800 uppercase">
                      VERBATIM CODE EVIDENCE IN YOUR REPO {lineNum ? `(LINE ${lineNum})` : ''}
                    </h5>
                    <span className="text-[11px] font-mono text-slate-600 bg-white px-2 py-0.5 rounded border border-slate-200">
                      {vuln.filePath}
                    </span>
                  </div>
                  <div className="border border-slate-200 bg-slate-900 rounded-xl p-3.5 font-mono text-xs text-emerald-400 overflow-x-auto shadow-xs">
                    <pre className="text-xs text-slate-100 whitespace-pre-wrap leading-relaxed">
                      {vuln.codeEvidence || vuln.codeSnippet}
                    </pre>
                  </div>
                </div>
              )}

              {/* Remediation & Action Section */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 pt-2">
                {/* Action Box: Push Fix directly or PR */}
                <div className="border border-slate-200 bg-white rounded-xl p-4 space-y-4 flex flex-col justify-between shadow-xs">
                  <div className="space-y-2">
                    <h5 className="text-xs font-bold text-[#1976d2] uppercase">
                      AUTOMATED FIX & CODE UPDATE
                    </h5>
                    <p className="text-xs text-slate-600 leading-relaxed font-sans">
                      Choose how you want to apply this verified patch to your GitHub repository:
                    </p>

                    {/* Success notification if fix was pushed */}
                    {fixSuccess && (
                      <div className="p-3 border border-blue-200 bg-blue-50 text-[#1976d2] rounded-xl space-y-2">
                        <div className="text-xs font-bold uppercase">
                          {fixSuccess.type === 'commit' 
                            ? (fixSuccess.isSandbox ? 'Verified Security Patch Applied (Sandbox)' : 'Code Updated in Repo')
                            : (fixSuccess.isSandbox ? 'Pull Request Drafted (Sandbox)' : 'Pull Request Created')}
                        </div>
                        <p className="text-[11px] text-slate-700">
                          {fixSuccess.type === 'commit' 
                            ? (fixSuccess.isSandbox 
                                ? `The finding '${vuln.title}' has been marked as resolved with the verified security patch. (To push direct commits to your GitHub account, configure a Personal Access Token with repo scope in User Settings).`
                                : `The file '${vuln.filePath}' has been patched and committed directly to branch '${fixSuccess.branch || 'main'}'.`)
                            : (fixSuccess.isSandbox
                                ? `A Pull Request proposal has been created and the finding marked active. (To open PRs directly on GitHub, configure a Personal Access Token in User Settings).`
                                : `A new branch and Pull Request has been opened on GitHub for code review.`)}
                        </p>
                        <a
                          href={fixSuccess.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-block text-xs font-semibold bg-[#1976d2] text-white px-3 py-1.5 rounded-lg hover:bg-blue-700 transition-colors"
                        >
                          {fixSuccess.type === 'commit' ? 'View Code on GitHub' : 'View Pull Requests'}
                        </a>
                      </div>
                    )}

                    {pushError && (
                      <div className="p-3 border border-red-200 bg-red-50 text-red-700 rounded-xl space-y-1">
                        <p className="text-xs font-bold uppercase">Fix Update Failed</p>
                        <p className="text-[11px] text-slate-700">{pushError}</p>
                      </div>
                    )}
                  </div>

                  <div className="space-y-2 pt-2">
                    <div className="flex flex-col sm:flex-row gap-2.5">
                      {/* Direct Push Button */}
                      <button
                        onClick={handlePushDirectFix}
                        disabled={pushingMode !== null || vuln.status === 'resolved'}
                        className="flex-1 github-btn-primary disabled:opacity-50 font-bold py-2.5 px-3 text-xs transition-all cursor-pointer shadow-xs"
                        title="Directly applies fix and commits to the default branch"
                      >
                        {pushingMode === 'commit' ? 'COMMITTING TO REPO...' : 'PUSH FIX DIRECTLY'}
                      </button>

                      {/* Pull Request Button */}
                      <button
                        onClick={handlePushPR}
                        disabled={pushingMode !== null || vuln.status === 'resolved'}
                        className="github-btn-secondary disabled:opacity-50 font-bold py-2.5 px-3 text-xs transition-all cursor-pointer"
                        title="Creates a new branch and opens a Pull Request"
                      >
                        {pushingMode === 'pr' ? 'CREATING PR...' : 'CREATE PULL REQUEST'}
                      </button>
                    </div>

                    <div className="flex items-center justify-between pt-1">
                      <button 
                        onClick={() => onStatusUpdate(vuln.status === 'resolved' ? 'open' : 'resolved')}
                        className="text-[11px] text-slate-500 hover:text-[#1976d2] uppercase font-semibold underline cursor-pointer"
                      >
                        {vuln.status === 'resolved' ? 'Re-open finding' : 'Manually Mark as Resolved'}
                      </button>
                    </div>
                  </div>
                </div>

                {/* Code Fix Patch View */}
                <div className="border border-slate-200 bg-white rounded-xl p-4 space-y-2 flex flex-col justify-between shadow-xs">
                  <div className="flex items-center justify-between">
                    <h5 className="text-xs font-bold text-slate-800 uppercase">
                      RECOMMENDED CODE FIX PATCH
                    </h5>
                    <button
                      onClick={handleCopyFix}
                      className="text-[11px] bg-slate-100 border border-slate-200 text-slate-700 hover:bg-slate-200 px-2.5 py-1 rounded-lg font-semibold transition-colors cursor-pointer"
                    >
                      {copied ? 'COPIED' : 'COPY CODE'}
                    </button>
                  </div>
                  
                  <div className="border border-slate-200 bg-slate-900 rounded-xl p-3 text-xs text-slate-100 font-mono max-h-72 overflow-y-auto shadow-inner">
                    <ReactMarkdown>{`\`\`\`typescript\n${vuln.fix || vuln.remediation}\n\`\`\``}</ReactMarkdown>
                  </div>

                  <p className="text-[11px] text-slate-500 font-sans">
                    Click "Push Fix Directly" to update this file automatically, or copy and paste the patch into your local workspace.
                  </p>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function getHealthScoreColor(score: number) {
  if (score >= 90) return 'text-emerald-600';
  if (score >= 70) return 'text-amber-600';
  if (score >= 50) return 'text-orange-500';
  return 'text-red-600';
}
