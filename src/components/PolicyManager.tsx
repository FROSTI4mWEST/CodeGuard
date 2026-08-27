import React, { useState, useEffect } from 'react';
import { db, auth, handleFirestoreError, OperationType } from '../lib/firebase';
import { collection, query, onSnapshot, orderBy, addDoc, deleteDoc, doc, updateDoc, serverTimestamp } from 'firebase/firestore';
import { motion, AnimatePresence } from 'motion/react';
import { type SecurityPolicy } from '../types';
import { generateSecurityPolicy } from '../lib/gemini';
import { VERIFIED_PATTERNS } from '../lib/securityAudit';

const PRESET_TOPICS = [
  { label: "Secrets Management", topic: "Secrets & API Key Management", desc: "Secret rotation, vault storage & scan gates" },
  { label: "SQL Injection Prevention", topic: "Database Parameterization & Injection Defense", desc: "Prepared statements & schema sanitization" },
  { label: "Auth & RBAC", topic: "Authentication, RBAC & Session Management", desc: "MFA, short-lived JWTs & role boundaries" },
  { label: "Supply Chain & SBOM", topic: "Dependency Auditing & Supply Chain Security", desc: "CVE blocking, lockfile hashing & SCA" },
  { label: "Container & Cloud", topic: "Docker & Cloud Infrastructure Hardening", desc: "Rootless containers, distroless & network policies" },
  { label: "API & CSP Headers", topic: "API Security & Browser Defense Headers", desc: "CSP, HSTS, rate limiting & CORS constraints" },
];

export function PolicyManager() {
  const [policies, setPolicies] = useState<SecurityPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [topic, setTopic] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [confirmingDeleteId, setConfirmingDeleteId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [newRuleInputs, setNewRuleInputs] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  useEffect(() => {
    const q = query(collection(db, 'policies'), orderBy('sortOrder', 'desc'));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const fetched = snapshot.docs.map(docSnap => ({ id: docSnap.id, ...docSnap.data() } as SecurityPolicy));
      setPolicies(fetched);
      setLoading(false);
    }, (err) => {
      console.warn("Firestore listener notice for policies:", err);
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const handleGenerate = async (topicToUse?: string) => {
    const targetTopic = (topicToUse || topic).trim();
    if (!targetTopic) return;

    setGenerating(true);
    setError(null);
    setSuccessNotice(null);

    try {
      const standards = VERIFIED_PATTERNS.map(p => `- ${p.category}: ${p.verifiedRemediation}`).join('\n');
      const data = await generateSecurityPolicy(targetTopic, standards);

      const path = 'policies';
      const now = Date.now();
      const newPolicyDoc = {
        name: data.name,
        description: data.description,
        rules: data.rules,
        sortOrder: now,
        createdAt: new Date().toISOString(),
        createdBy: auth.currentUser?.uid || 'security-officer',
      };

      try {
        const docRef = await addDoc(collection(db, path), {
          ...newPolicyDoc,
          createdAt: serverTimestamp(),
        });
        
        // Optimistically append if listener is delayed
        setPolicies(prev => [{ id: docRef.id, ...newPolicyDoc }, ...prev.filter(p => p.id !== docRef.id)]);
      } catch (fErr) {
        console.warn("Local storage fallback for policy creation:", fErr);
        // Fallback local persistence if Firestore connection is transient
        const localId = `local-policy-${now}`;
        setPolicies(prev => [{ id: localId, ...newPolicyDoc }, ...prev]);
      }

      setTopic('');
      setSuccessNotice(`Successfully drafted policy: "${data.name}"`);
      setTimeout(() => setSuccessNotice(null), 4000);
    } catch (err: any) {
      console.error("Policy Generation Error:", err);
      setError(err.message || "Failed to generate policy. Please try again.");
    } finally {
      setGenerating(false);
    }
  };

  const handleDelete = async (policy: SecurityPolicy) => {
    const policyId = policy.id;
    setDeletingId(policyId);
    setConfirmingDeleteId(null);
    setError(null);

    try {
      try {
        await deleteDoc(doc(db, 'policies', policyId));
      } catch (fErr) {
        console.warn("Firestore delete failed, deleting locally:", fErr);
      }
      setPolicies(prev => prev.filter(p => p.id !== policyId));
      setSuccessNotice(`Policy "${policy.name}" was permanently removed.`);
      setTimeout(() => setSuccessNotice(null), 4000);
    } catch (err: any) {
      console.error("Delete policy error:", err);
      setError("Failed to delete policy: " + (err.message || String(err)));
    } finally {
      setDeletingId(null);
    }
  };

  const handleDeleteRule = async (policy: SecurityPolicy, ruleIndex: number) => {
    const updatedRules = policy.rules.filter((_, idx) => idx !== ruleIndex);
    try {
      await updateDoc(doc(db, 'policies', policy.id), {
        rules: updatedRules,
      });
      setPolicies(prev => prev.map(p => p.id === policy.id ? { ...p, rules: updatedRules } : p));
    } catch (err) {
      console.warn("Could not update rules in Firestore, updating locally:", err);
      setPolicies(prev => prev.map(p => p.id === policy.id ? { ...p, rules: updatedRules } : p));
    }
  };

  const handleAddRule = async (policy: SecurityPolicy) => {
    const input = newRuleInputs[policy.id]?.trim();
    if (!input) return;

    const updatedRules = [...policy.rules, input];
    try {
      await updateDoc(doc(db, 'policies', policy.id), {
        rules: updatedRules,
      });
      setPolicies(prev => prev.map(p => p.id === policy.id ? { ...p, rules: updatedRules } : p));
      setNewRuleInputs(prev => ({ ...prev, [policy.id]: '' }));
    } catch (err) {
      console.warn("Local update for rule:", err);
      setPolicies(prev => prev.map(p => p.id === policy.id ? { ...p, rules: updatedRules } : p));
      setNewRuleInputs(prev => ({ ...prev, [policy.id]: '' }));
    }
  };

  const handleCopy = (policy: SecurityPolicy) => {
    const text = `# ${policy.name}\n${policy.description}\n\n## Mandatory Enforcement Rules:\n${policy.rules.map((r, i) => `${i + 1}. ${r}`).join('\n')}`;
    navigator.clipboard.writeText(text);
    setCopiedId(policy.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportMarkdown = (policy: SecurityPolicy) => {
    const markdown = `# ${policy.name}
**Standard:** OWASP Top 10 & CIS Benchmarks
**Created:** ${formatDate(policy.createdAt)}

## Description
${policy.description}

## Security Enforcement Rules
${policy.rules.map((r, i) => `${i + 1}. ${r}`).join('\n')}

---
*Generated by CodeGuard Security Governance Engine*
`;
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${policy.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const formatDate = (date: any) => {
    if (!date) return 'ACTIVE';
    if (typeof date.toDate === 'function') {
      return date.toDate().toLocaleDateString();
    }
    try {
      return new Date(date).toLocaleDateString();
    } catch {
      return 'ACTIVE';
    }
  };

  const filteredPolicies = policies.filter(p => 
    p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    p.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
    p.rules.some(r => r.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-6xl mx-auto space-y-6 pb-12 font-sans"
    >
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-xl font-bold tracking-tight text-slate-950">Security Policies & Rules</h2>
            <span className="text-xs px-2 py-0.5 bg-slate-50 text-slate-700 border border-slate-200 rounded-md font-medium">
              {policies.length} Active
            </span>
          </div>
          <p className="text-slate-500 text-xs mt-0.5">Security standards and automated enforcement rules for your repositories.</p>
        </div>
      </div>

      {/* Success / Notification Banner */}
      <AnimatePresence>
        {successNotice && (
          <motion.div 
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="p-3.5 border border-slate-200 bg-slate-50 text-slate-800 rounded-lg text-xs flex items-center gap-2 shadow-2xs"
          >
            <span className="font-semibold">{successNotice}</span>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Policy Draftsman */}
        <div className="lg:col-span-4 space-y-6">
          <div className="border border-slate-200 bg-white p-5 rounded-xl shadow-xs">
            <h3 className="text-sm font-semibold mb-1 text-slate-950 uppercase tracking-wider">Policy Generator</h3>
            <p className="text-slate-500 text-xs leading-relaxed mb-4">
              Enter any security domain or requirement to create a structured compliance policy.
            </p>

            <form onSubmit={(e) => { e.preventDefault(); handleGenerate(); }} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-800">Policy Topic</label>
                <input 
                  type="text" 
                  value={topic}
                  onChange={(e) => setTopic(e.target.value)}
                  placeholder="e.g. Secrets Rotation & Key Storage"
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-slate-400 focus:bg-white transition-all"
                  required
                />
              </div>

              {error && (
                <div className="p-3 border border-red-200 bg-red-50 text-red-700 rounded-lg text-xs">
                  {error}
                </div>
              )}

              <button 
                type="submit" 
                disabled={generating || !topic.trim()}
                className="w-full rounded-lg bg-slate-950 hover:bg-slate-800 text-white py-2 px-4 text-xs font-medium flex items-center justify-center gap-2 cursor-pointer shadow-xs disabled:opacity-50"
              >
                {generating ? 'Drafting Policy…' : 'Generate Policy'}
              </button>
            </form>
          </div>

          {/* Quick Domain Presets */}
          <div className="border border-slate-200 bg-white p-5 rounded-xl shadow-xs space-y-3">
            <h4 className="text-xs font-semibold text-slate-950 uppercase tracking-wider">
              Common Policy Templates
            </h4>
            <p className="text-[11px] text-slate-500">Quick-start standard security guidelines:</p>
            
            <div className="space-y-2 pt-1">
              {PRESET_TOPICS.map((preset, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setTopic(preset.topic);
                    handleGenerate(preset.topic);
                  }}
                  disabled={generating}
                  className="w-full text-left p-3 bg-slate-50/50 hover:bg-slate-100/70 border border-slate-200 rounded-lg transition-all group cursor-pointer"
                >
                  <div className="flex items-center justify-between text-xs font-semibold text-slate-900 group-hover:text-slate-950">
                    <span>{preset.label}</span>
                  </div>
                  <p className="text-[11px] text-slate-500 mt-0.5">{preset.desc}</p>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Policy List & Management */}
        <div className="lg:col-span-8 space-y-4">
          {/* Search & Filter Bar */}
          <div className="flex items-center justify-between gap-3 border border-slate-200 bg-white p-3 rounded-xl shadow-xs">
            <div className="flex items-center gap-2 flex-1">
              <input 
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search active policies or specific enforcement rules..."
                className="w-full bg-transparent text-xs text-slate-800 placeholder-slate-400 focus:outline-none px-2"
              />
            </div>
            {searchQuery && (
              <button 
                onClick={() => setSearchQuery('')}
                className="text-[11px] text-slate-500 hover:text-slate-800 uppercase font-semibold cursor-pointer"
              >
                Clear
              </button>
            )}
          </div>

          {loading ? (
            <div className="border border-slate-200 bg-white rounded-2xl p-12 text-center shadow-xs space-y-3">
              <p className="text-xs text-slate-600 font-bold uppercase tracking-wider">SYNCING INSTITUTIONAL SECURITY POLICIES...</p>
            </div>
          ) : filteredPolicies.length === 0 ? (
            <div className="border border-slate-200 bg-white rounded-2xl p-12 text-center border-dashed space-y-3">
              <p className="text-slate-700 text-xs font-bold uppercase tracking-widest">
                {searchQuery ? 'NO POLICIES MATCH SEARCH CRITERIA' : 'NO ACTIVE POLICIES STORED'}
              </p>
              <p className="text-[11px] text-slate-500">Use the Policy Draftsman or choose a quick preset on the left.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredPolicies.map((policy) => (
                <div key={policy.id} className="border border-slate-200 bg-white p-5 rounded-2xl shadow-xs space-y-4">
                  {/* Card Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
                    <div>
                      <h4 className="text-sm font-bold text-slate-900 uppercase">{policy.name}</h4>
                      <span className="text-[11px] text-slate-500">
                        Enforced standard • {formatDate(policy.createdAt)}
                      </span>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 self-end sm:self-auto">
                      <button
                        onClick={() => handleCopy(policy)}
                        className="px-2.5 py-1.5 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-lg text-xs font-semibold text-slate-700 transition-colors cursor-pointer"
                        title="Copy policy to clipboard"
                      >
                        <span>{copiedId === policy.id ? 'COPIED!' : 'COPY'}</span>
                      </button>

                      <button
                        onClick={() => handleExportMarkdown(policy)}
                        className="px-2.5 py-1.5 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-lg text-xs font-semibold text-slate-700 transition-colors cursor-pointer"
                        title="Download Markdown Document"
                      >
                        <span>EXPORT</span>
                      </button>

                      {confirmingDeleteId === policy.id ? (
                        <div className="flex items-center gap-1 bg-red-50 border border-red-200 rounded-lg p-0.5">
                          <button
                            onClick={() => handleDelete(policy)}
                            disabled={deletingId === policy.id}
                            className="px-2.5 py-1 bg-red-600 hover:bg-red-700 text-white font-bold text-[11px] rounded-md transition-colors cursor-pointer"
                          >
                            <span>{deletingId === policy.id ? 'DELETING...' : 'CONFIRM'}</span>
                          </button>
                          <button
                            onClick={() => setConfirmingDeleteId(null)}
                            className="px-2 py-1 text-red-600 hover:bg-red-100 text-[11px] rounded-md transition-colors cursor-pointer font-semibold"
                          >
                            CANCEL
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setConfirmingDeleteId(policy.id)}
                          className="px-2.5 py-1.5 bg-slate-50 hover:bg-red-50 border border-slate-200 hover:border-red-200 rounded-lg text-xs font-semibold text-red-600 transition-colors cursor-pointer"
                          title="Delete policy"
                        >
                          <span>DELETE</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Description */}
                  <p className="text-slate-600 text-xs leading-relaxed">{policy.description}</p>

                  {/* Rules Grid */}
                  <div className="space-y-2">
                    <div className="text-[11px] font-bold text-slate-800 uppercase tracking-wider">
                      Enforced Defense Rules ({policy.rules?.length || 0})
                    </div>
                    <div className="grid grid-cols-1 gap-2">
                      {policy.rules?.map((rule, idx) => (
                        <div key={idx} className="flex items-start justify-between gap-2.5 p-3 bg-[#f8fafc] border border-slate-200 rounded-xl group/rule">
                          <div className="flex items-start gap-2.5">
                            <span className="text-xs font-mono font-bold text-[#1976d2]">{idx + 1}.</span>
                            <span className="text-xs text-slate-800 leading-snug">{rule}</span>
                          </div>
                          <button
                            onClick={() => handleDeleteRule(policy, idx)}
                            className="opacity-0 group-hover/rule:opacity-100 text-slate-400 hover:text-red-600 text-[11px] font-semibold transition-all px-1.5 py-0.5 shrink-0 cursor-pointer"
                            title="Remove this rule"
                          >
                            REMOVE
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Add Custom Rule Input */}
                  <div className="pt-2 flex items-center gap-2">
                    <input 
                      type="text" 
                      value={newRuleInputs[policy.id] || ''}
                      onChange={(e) => setNewRuleInputs(prev => ({ ...prev, [policy.id]: e.target.value }))}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault();
                          handleAddRule(policy);
                        }
                      }}
                      placeholder="Append custom institutional rule to this policy..."
                      className="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2 text-xs text-slate-800 focus:outline-none focus:border-[#1976d2] focus:bg-white"
                    />
                    <button
                      onClick={() => handleAddRule(policy)}
                      disabled={!newRuleInputs[policy.id]?.trim()}
                      className="px-3.5 py-2 github-btn-primary disabled:opacity-40 text-xs cursor-pointer shadow-xs font-semibold"
                    >
                      <span>ADD RULE</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}
