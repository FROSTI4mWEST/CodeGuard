import React, { useState, useEffect } from 'react';
import { db, auth, handleFirestoreError, OperationType } from '../lib/firebase';
import { collection, query, where, onSnapshot, addDoc, serverTimestamp } from 'firebase/firestore';
import { GithubAuthProvider, signInWithPopup } from 'firebase/auth';
import { motion, AnimatePresence } from 'motion/react';
import { Github, Globe2, Plus } from 'lucide-react';
import { type Repository } from '../types';
import { fetchUserRepositories, fetchPublicReposForUser } from '../lib/github';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { VulnerabilityDensityMap } from './VulnerabilityDensityMap';
import { LiveUrlScanner } from './LiveUrlScanner';

function formatDate(ts: any): string {
  if (!ts) return 'NEVER';
  if (typeof ts === 'string') return new Date(ts).toLocaleString();
  if (ts.seconds) return new Date(ts.seconds * 1000).toLocaleString();
  if (ts.toDate && typeof ts.toDate === 'function') return ts.toDate().toLocaleString();
  return 'NEVER';
}

interface GitHubRepoItem {
  id: number;
  name: string;
  full_name: string;
  owner: { login: string; avatar_url?: string };
  html_url: string;
  description: string | null;
  private: boolean;
  language: string | null;
  stargazers_count: number;
  forks_count: number;
  updated_at: string;
}

export function Dashboard({ onRepoSelect }: { onRepoSelect: (id: string) => void }) {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [modalTab, setModalTab] = useState<'my_repos' | 'live_url'>('my_repos');
  const [error, setError] = useState<string | null>(null);

  // Auto-detected GitHub Repos State
  const [ghRepos, setGhRepos] = useState<GitHubRepoItem[]>([]);
  const [loadingGhRepos, setLoadingGhRepos] = useState(false);
  const [ghRepoSearch, setGhRepoSearch] = useState('');
  const [ghAuthRequired, setGhAuthRequired] = useState(false);
  const [customUsername, setCustomUsername] = useState('');
  const [customPat, setCustomPat] = useState('');
  const [importingRepoId, setImportingRepoId] = useState<string | null>(null);
  const [showPatInput, setShowPatInput] = useState(false);

  useEffect(() => {
    if (!auth.currentUser) {
      setLoading(false);
      return;
    }

    // STRICT USER ISOLATION: Query repositories added by the current authenticated user only
    const q = query(
      collection(db, 'repositories'),
      where('addedBy', '==', auth.currentUser.uid)
    );

    const unsubscribe = onSnapshot(q, (snapshot) => {
      const reposData = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as Repository));
      reposData.sort((a, b) => {
        const timeA = (a.createdAt as any)?.seconds || 0;
        const timeB = (b.createdAt as any)?.seconds || 0;
        return timeB - timeA;
      });
      setRepos(reposData);
      setLoading(false);
    }, (err) => {
      handleFirestoreError(err, OperationType.LIST, 'repositories');
    });

    return () => unsubscribe();
  }, [auth.currentUser?.uid]);

  // Load authenticated user's GitHub Repositories automatically
  const loadUserGithubRepos = async (tokenOverride?: string) => {
    setLoadingGhRepos(true);
    setError(null);
    setGhAuthRequired(false);

    try {
      const token = tokenOverride || localStorage.getItem('github_access_token') || undefined;
      const data = await fetchUserRepositories(token);
      setGhRepos(data as unknown as GitHubRepoItem[]);
    } catch (err: any) {
      console.warn("Could not load authenticated GitHub repos:", err);
      const isGitHubLinked = auth.currentUser?.providerData?.some(p => p.providerId === 'github.com');
      if (!localStorage.getItem('github_access_token') && !isGitHubLinked) {
        setGhAuthRequired(true);
      } else {
        const emailPrefix = auth.currentUser?.email?.split('@')[0];
        if (emailPrefix) {
          try {
            const publicData = await fetchPublicReposForUser(emailPrefix);
            setGhRepos(publicData as unknown as GitHubRepoItem[]);
            return;
          } catch {
            // ignore
          }
        }
        setGhAuthRequired(true);
      }
    } finally {
      setLoadingGhRepos(false);
    }
  };

  const linkGitHubForRepos = async () => {
    setLoadingGhRepos(true);
    setError(null);
    try {
      const provider = new GithubAuthProvider();
      provider.addScope('repo');
      provider.addScope('read:user');
      const result = await signInWithPopup(auth, provider);
      const credential = GithubAuthProvider.credentialFromResult(result);
      if (credential?.accessToken) {
        localStorage.setItem('github_access_token', credential.accessToken);
        await loadUserGithubRepos(credential.accessToken);
      } else {
        await loadUserGithubRepos();
      }
    } catch (err: any) {
      console.error("GitHub linking error:", err);
      setError(err.message || "Failed to authenticate with GitHub.");
      setLoadingGhRepos(false);
    }
  };

  const handleFetchByUsername = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customUsername.trim()) return;
    setLoadingGhRepos(true);
    setError(null);
    try {
      const data = await fetchPublicReposForUser(customUsername.trim());
      setGhRepos(data as unknown as GitHubRepoItem[]);
      setGhAuthRequired(false);
    } catch (err: any) {
      setError(`Could not find public repositories for GitHub user '${customUsername}'.`);
    } finally {
      setLoadingGhRepos(false);
    }
  };

  const handleSavePat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customPat.trim()) return;
    localStorage.setItem('github_access_token', customPat.trim());
    setShowPatInput(false);
    await loadUserGithubRepos(customPat.trim());
  };

  useEffect(() => {
    if (showAddModal && modalTab === 'my_repos' && ghRepos.length === 0) {
      loadUserGithubRepos();
    }
  }, [showAddModal, modalTab]);

  const handleImportGithubRepo = async (ghRepo: GitHubRepoItem) => {
    if (!auth.currentUser) return;
    setImportingRepoId(ghRepo.full_name);
    setError(null);

    const alreadyExists = repos.some(r => r.full_name.toLowerCase() === ghRepo.full_name.toLowerCase());
    if (alreadyExists) {
      setError(`Repository ${ghRepo.full_name} is already connected.`);
      setImportingRepoId(null);
      return;
    }

    try {
      const newRepo = {
        name: ghRepo.name,
        owner: ghRepo.owner.login,
        full_name: ghRepo.full_name,
        url: ghRepo.html_url,
        visibility: ghRepo.private ? 'private' : 'public',
        createdAt: serverTimestamp(),
        addedBy: auth.currentUser.uid,
        healthScore: 100,
      };

      const docRef = await addDoc(collection(db, 'repositories'), newRepo);
      setShowAddModal(false);
      onRepoSelect(docRef.id);
    } catch (fError) {
      handleFirestoreError(fError, OperationType.CREATE, 'repositories');
    } finally {
      setImportingRepoId(null);
    }
  };

  const criticalIssues = repos.reduce((acc, repo) => acc + (repo.healthScore && repo.healthScore < 50 ? 1 : 0), 0);

  const filteredGhRepos = ghRepos.filter(r => 
    r.full_name.toLowerCase().includes(ghRepoSearch.toLowerCase()) ||
    (r.language && r.language.toLowerCase().includes(ghRepoSearch.toLowerCase())) ||
    (r.description && r.description.toLowerCase().includes(ghRepoSearch.toLowerCase()))
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-7xl mx-auto space-y-6 pb-12 font-sans"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-950">Security Targets</h2>
          <p className="text-slate-500 text-xs mt-0.5">Continuous security monitoring for repositories and live web applications.</p>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={() => { setShowAddModal(true); setModalTab('live_url'); }} 
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 shadow-2xs hover:bg-slate-50 transition-colors cursor-pointer"
          >
            <Globe2 className="h-3.5 w-3.5 text-slate-500" />
            <span>Scan Live URL</span>
          </button>
          <button 
            onClick={() => { setShowAddModal(true); setModalTab('my_repos'); }} 
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-950 px-3.5 py-2 text-xs font-medium text-white shadow-xs hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Add Repository</span>
          </button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Repositories" value={repos.length.toString()} />
        <StatCard label="Critical Findings" value={criticalIssues.toString()} />
        <StatCard label="Average Health" value={repos.length > 0 ? (repos.reduce((a, b) => a + (b.healthScore || 0), 0) / repos.length).toFixed(0) + '%' : '--'} />
        <StatCard label="Passing Targets" value={repos.filter(r => (r.healthScore || 0) >= 90).length.toString()} />
      </div>

      {/* Vulnerability Density Map */}
      {repos.length > 0 && (
        <VulnerabilityDensityMap repos={repos} onRepoSelect={onRepoSelect} />
      )}

      {/* Visual Analytics */}
      {repos.length > 0 && (
        <div className="border border-slate-200 bg-white rounded-xl p-6 shadow-xs">
          <h3 className="text-sm font-bold mb-6 text-slate-800 uppercase">
            Infrastructure Security Distribution
          </h3>
          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={repos} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis 
                  dataKey="name" 
                  axisLine={{ stroke: '#cbd5e1' }} 
                  tickLine={false} 
                  tick={{ fill: '#64748b', fontSize: 11, fontFamily: 'monospace' }}
                />
                <YAxis 
                  axisLine={{ stroke: '#cbd5e1' }} 
                  tickLine={false} 
                  tick={{ fill: '#64748b', fontSize: 11, fontFamily: 'monospace' }}
                  domain={[0, 100]}
                />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #cbd5e1', borderRadius: '8px', color: '#0f172a', boxShadow: '0 2px 4px rgba(0,0,0,0.05)' }}
                  labelStyle={{ color: '#0f172a', fontWeight: 'bold' }}
                />
                <Bar dataKey="healthScore" radius={[4, 4, 0, 0]}>
                  {repos.map((repo, index) => (
                    <Cell key={`cell-${index}`} fill={repo.healthScore && repo.healthScore >= 90 ? '#0f172a' : repo.healthScore && repo.healthScore >= 70 ? '#64748b' : '#ef4444'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Repository List */}
      <div className="border border-slate-200 bg-white rounded-xl shadow-xs overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="text-xs font-semibold text-slate-900 uppercase tracking-wider">
            Connected Repositories ({repos.length})
          </div>
          <span className="text-[11px] text-slate-400 font-medium">Automatic Scanning</span>
        </div>

        {loading ? (
          <div className="p-12 text-center text-slate-500 text-xs">
            <p>Loading repositories...</p>
          </div>
        ) : repos.length === 0 ? (
          <div className="p-12 text-center border-b border-slate-100 space-y-4">
            <p className="text-slate-600 font-medium text-xs">No repositories connected yet</p>
            <div className="flex flex-wrap items-center justify-center gap-3">
              <button 
                onClick={() => { setShowAddModal(true); setModalTab('my_repos'); }} 
                className="bg-slate-950 hover:bg-slate-800 text-white font-medium text-xs px-4 py-2 rounded-md cursor-pointer shadow-xs transition-colors flex items-center gap-2"
              >
                <Github className="w-4 h-4" />
                <span>Auto-Detect GitHub Repos</span>
              </button>
              <button 
                onClick={() => { setShowAddModal(true); setModalTab('live_url'); }} 
                className="border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 font-medium text-xs px-4 py-2 rounded-md cursor-pointer shadow-2xs transition-colors"
              >
                Scan a Live URL
              </button>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {repos.map((repo) => (
              <div 
                key={repo.id}
                onClick={() => onRepoSelect(repo.id)}
                className="flex items-center gap-4 px-5 py-4 hover:bg-slate-50 transition-colors cursor-pointer group"
              >
                <Github className="w-4 h-4 text-slate-700 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-semibold text-slate-900 group-hover:text-slate-950 transition-colors truncate">{repo.full_name}</h4>
                    <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded-md border ${repo.visibility === 'private' ? 'bg-slate-900 text-white border-slate-900' : 'bg-slate-50 text-slate-700 border-slate-200'}`}>
                      {repo.visibility}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 mt-0.5 text-[11px] text-slate-400">
                    <span>Last scanned: {formatDate(repo.lastScanDate)}</span>
                  </div>
                </div>

                <div className="flex items-center gap-6">
                  <div className="text-right">
                    <div className="text-[10px] text-slate-400 uppercase font-semibold">Score</div>
                    <div className={`text-base font-bold font-mono ${getScoreColor(repo.healthScore || 0)}`}>
                      {repo.healthScore || '--'}%
                    </div>
                  </div>
                  <span className="text-xs font-semibold text-slate-400 group-hover:text-slate-950 transition-colors">View</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Connect Modal */}
      <AnimatePresence>
        {showAddModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-slate-900/60 backdrop-blur-xs" 
              onClick={() => setShowAddModal(false)}
            />
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className={`relative bg-white border border-slate-200 w-full ${
                modalTab === 'live_url' ? 'max-w-4xl' : 'max-w-xl'
              } rounded-2xl shadow-xl overflow-hidden font-sans max-h-[92vh] flex flex-col`}
            >
              {/* Header */}
              <div className="px-6 py-4 border-b border-slate-200 bg-white flex items-center justify-between shrink-0">
                <div>
                  <h3 className="font-semibold text-slate-950 text-sm">
                    Connect Security Target
                  </h3>
                  <p className="text-slate-500 text-xs mt-0.5">Select a GitHub repository or scan a live website URL.</p>
                </div>
                <button 
                  onClick={() => setShowAddModal(false)} 
                  className="text-slate-400 hover:text-slate-700 transition-colors cursor-pointer p-1 rounded-md hover:bg-slate-100 text-xs font-medium"
                >
                  Close
                </button>
              </div>

              {/* Navigation Tabs */}
              <div className="px-6 pt-3 pb-1 border-b border-slate-100 bg-white shrink-0">
                <div className="flex gap-1 bg-slate-100 p-1 rounded-lg text-xs font-medium">
                  <button
                    onClick={() => setModalTab('my_repos')}
                    className={`flex-1 py-1.5 px-3 flex items-center justify-center gap-2 rounded-md transition-all cursor-pointer ${
                      modalTab === 'my_repos'
                        ? 'bg-white text-slate-950 shadow-2xs font-semibold'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <Github className="w-3.5 h-3.5" />
                    <span>My Repositories</span>
                  </button>
                  <button
                    onClick={() => setModalTab('live_url')}
                    className={`flex-1 py-1.5 px-3 flex items-center justify-center gap-2 rounded-md transition-all cursor-pointer ${
                      modalTab === 'live_url'
                        ? 'bg-white text-slate-950 shadow-2xs font-semibold'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <Globe2 className="w-3.5 h-3.5" /> 
                    <span>Live URL Scan</span>
                  </button>
                </div>
              </div>

              {/* Body */}
              <div className={`${modalTab === 'live_url' ? 'p-6' : 'p-5'} space-y-4 overflow-y-auto flex-1 bg-slate-50/50`}>
                {error && (
                  <div className="p-3 border border-red-200 bg-red-50 text-red-700 rounded-lg text-xs">
                    <span>{error}</span>
                  </div>
                )}

                {modalTab === 'my_repos' ? (
                  <div className="space-y-3">
                    {/* Filter / Search Box */}
                    <div className="relative">
                      <input
                        type="text"
                        value={ghRepoSearch}
                        onChange={(e) => setGhRepoSearch(e.target.value)}
                        placeholder="Filter your repositories by name, language..."
                        className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2.5 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-[#1976d2] focus:ring-1 focus:ring-[#1976d2] shadow-xs"
                      />
                    </div>

                    {/* Action Row */}
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => loadUserGithubRepos()}
                        disabled={loadingGhRepos}
                        className="border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs rounded-lg px-3.5 py-1.5 shadow-xs transition-colors disabled:opacity-50 cursor-pointer"
                      >
                        {loadingGhRepos ? 'Refreshing...' : 'Refresh'}
                      </button>
                      <button
                        onClick={() => setShowPatInput(!showPatInput)}
                        className="border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 px-3 py-1.5 text-xs font-medium rounded-lg shadow-xs transition-colors cursor-pointer"
                        title="Configure GitHub Personal Access Token"
                      >
                        Configure Token (PAT)
                      </button>
                    </div>

                    {/* PAT Input Expandable */}
                    {showPatInput && (
                      <form onSubmit={handleSavePat} className="p-3.5 border border-slate-200 bg-white rounded-xl space-y-2 shadow-xs">
                        <div className="flex items-center justify-between">
                          <label className="text-[11px] font-bold text-slate-800 uppercase">GitHub Personal Access Token (PAT)</label>
                          <span className="text-[10px] text-slate-500">Stored locally in browser</span>
                        </div>
                        <div className="flex gap-2">
                          <input
                            type="password"
                            value={customPat}
                            onChange={(e) => setCustomPat(e.target.value)}
                            placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                            className="flex-1 bg-white border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-[#1976d2]"
                          />
                          <button type="submit" className="bg-[#1976d2] hover:bg-[#1565c0] text-white font-medium px-3.5 py-1.5 rounded-lg text-xs cursor-pointer">Save</button>
                        </div>
                      </form>
                    )}

                    {/* Repository List */}
                    {loadingGhRepos ? (
                      <div className="p-12 text-center text-slate-500 text-xs space-y-2 bg-white border border-slate-200 rounded-xl">
                        <p>FETCHING YOUR GITHUB REPOSITORIES...</p>
                      </div>
                    ) : ghRepos.length > 0 ? (
                      <div className="bg-white border border-slate-200 rounded-xl shadow-xs divide-y divide-slate-200 overflow-hidden max-h-[380px] overflow-y-auto">
                        {filteredGhRepos.length === 0 ? (
                          <div className="p-8 text-center text-xs text-slate-500">
                            No repositories matching "{ghRepoSearch}"
                          </div>
                        ) : (
                          filteredGhRepos.map((gh) => {
                            const isConnected = repos.some(r => r.full_name.toLowerCase() === gh.full_name.toLowerCase());
                            const isImporting = importingRepoId === gh.full_name;

                            return (
                              <div 
                                key={gh.id}
                                className="p-3.5 flex items-center justify-between gap-3 hover:bg-slate-50/80 transition-colors"
                              >
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className="font-bold text-xs text-slate-900 tracking-tight">{gh.full_name}</span>
                                    <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded uppercase ${gh.private ? 'bg-[#8D4F27] text-white' : 'bg-slate-100 text-slate-700 border border-slate-300'}`}>
                                      {gh.private ? 'PRIVATE' : 'PUBLIC'}
                                    </span>
                                    {gh.language && (
                                      <span className="text-[10px] text-slate-600 font-semibold px-1.5 py-0.2 bg-slate-100 border border-slate-200 rounded">
                                        {gh.language}
                                      </span>
                                    )}
                                  </div>
                                  {gh.description && (
                                    <p className="text-[11px] text-slate-500 truncate mt-0.5">{gh.description}</p>
                                  )}
                                  <div className="flex items-center gap-3 text-[11px] text-slate-500 mt-1.5">
                                    <span>Stars: {gh.stargazers_count}</span>
                                    <span>Forks: {gh.forks_count}</span>
                                    <span>Updated: {new Date(gh.updated_at).toLocaleDateString()}</span>
                                  </div>
                                </div>

                                <div className="shrink-0">
                                  {isConnected ? (
                                    <span className="inline-flex items-center text-xs font-bold text-[#0043ce] bg-[#d0e2ff] border border-[#a6c8ff] px-3 py-1.5 rounded-lg shadow-xs">
                                      CONNECTED
                                    </span>
                                  ) : (
                                    <button
                                      onClick={() => handleImportGithubRepo(gh)}
                                      disabled={isImporting}
                                      className="bg-[#e8f1fe] hover:bg-[#d2e3fc] text-[#1967d2] border border-[#c2e7ff] font-bold px-3 py-1.5 text-xs rounded-lg cursor-pointer shadow-xs transition-colors"
                                    >
                                      {isImporting ? 'IMPORTING...' : 'IMPORT'}
                                    </button>
                                  )}
                                </div>
                              </div>
                            );
                          })
                        )}
                      </div>
                    ) : (
                      /* No repos loaded yet or token required */
                      <div className="p-6 border border-slate-200 bg-white rounded-xl space-y-4 text-center shadow-xs">
                        <div className="space-y-1">
                          <h4 className="text-xs font-bold text-slate-800 uppercase">Connect GitHub Account</h4>
                          <p className="text-xs text-slate-500 max-w-md mx-auto">
                            Authorize CodeGuard to automatically list your public and private repositories for instant security auditing.
                          </p>
                        </div>

                        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
                          <button
                            onClick={linkGitHubForRepos}
                            className="bg-[#1976d2] hover:bg-[#1565c0] text-white font-medium text-xs px-4 py-2 rounded-lg justify-center cursor-pointer shadow-xs transition-colors"
                          >
                            Authorize GitHub Access
                          </button>
                        </div>

                        <div className="relative py-2">
                          <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-slate-200"></div></div>
                          <div className="relative flex justify-center text-[10px] uppercase"><span className="bg-white px-2 text-slate-400 font-semibold">Or Fetch by Username</span></div>
                        </div>

                        {/* Search by Public Username */}
                        <form onSubmit={handleFetchByUsername} className="flex gap-2 max-w-sm mx-auto">
                          <input
                            type="text"
                            value={customUsername}
                            onChange={(e) => setCustomUsername(e.target.value)}
                            placeholder="Enter GitHub username (e.g. torvalds)"
                            className="flex-1 bg-white border border-slate-300 rounded-lg px-3 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-[#1976d2]"
                          />
                          <button type="submit" className="border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs px-3 py-1.5 rounded-lg cursor-pointer">
                            Search
                          </button>
                        </form>
                      </div>
                    )}
                  </div>
                ) : <LiveUrlScanner />}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function StatCard({ label, value }: { label: string, value: string }) {
  return (
    <div className="border border-slate-200 bg-white rounded-xl p-5 shadow-xs">
      <div className="text-slate-500 mb-2">
        <span className="text-[11px] font-bold uppercase tracking-wider">{label}</span>
      </div>
      <div className="text-2xl font-bold font-mono text-slate-900">{value}</div>
    </div>
  );
}

function getScoreColor(score: number) {
  if (score >= 90) return 'text-emerald-600';
  if (score >= 70) return 'text-amber-500';
  if (score >= 50) return 'text-orange-500';
  return 'text-red-500';
}
