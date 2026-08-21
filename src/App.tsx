import React, { useState, useEffect } from 'react';
import { auth, db, handleFirestoreError, OperationType } from './lib/firebase';
import { onAuthStateChanged, signInWithPopup, GithubAuthProvider, GoogleAuthProvider, signOut, User } from 'firebase/auth';
import { doc, getDoc, setDoc, serverTimestamp } from 'firebase/firestore';
import { motion, AnimatePresence } from 'motion/react';
import { Github, Terminal } from 'lucide-react';
import { Dashboard } from './components/Dashboard';
import { RepoAudit } from './components/RepoAudit';
import { PolicyManager } from './components/PolicyManager';
import { LandingPage } from './components/LandingPage';
import { TerminalConsole } from './components/TerminalConsole';
import { UserSettingsModal } from './components/UserSettingsModal';
import { type UserProfile, type UserRole } from './types';

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  
  // Active navigation tab: 'dashboard' | 'network' (repos) | 'decrypt' (policies) | 'terminal'
  const [activeTab, setActiveTab] = useState<'dashboard' | 'network' | 'decrypt' | 'terminal'>('dashboard');
  const [selectedRepoId, setSelectedRepoId] = useState<string | null>(null);
  const [showSettingsModal, setShowSettingsModal] = useState(false);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      setUser(firebaseUser);
      if (firebaseUser) {
        const profilePath = `users/${firebaseUser.uid}`;
        const profileRef = doc(db, 'users', firebaseUser.uid);
        
        try {
          const profileSnap = await getDoc(profileRef);
          if (profileSnap.exists()) {
            const data = profileSnap.data();
            setProfile({
              uid: firebaseUser.uid,
              email: firebaseUser.email || (data.email as string) || '',
              displayName: (data.displayName as string) || firebaseUser.displayName || firebaseUser.email?.split('@')[0] || 'Developer',
              photoURL: (data.photoURL as string) || firebaseUser.photoURL || '',
              role: (data.role as UserRole) || 'developer',
              createdAt: data.createdAt ? (typeof data.createdAt === 'string' ? data.createdAt : (data.createdAt.toDate?.()?.toISOString() || new Date().toISOString())) : new Date().toISOString(),
            });
          } else {
            const newProfile: UserProfile = {
              uid: firebaseUser.uid,
              email: firebaseUser.email || '',
              displayName: firebaseUser.displayName || firebaseUser.email?.split('@')[0] || 'Developer',
              photoURL: firebaseUser.photoURL || '',
              role: 'developer',
              createdAt: new Date().toISOString(),
            };
            try {
              await setDoc(profileRef, { ...newProfile, createdAt: serverTimestamp() });
              setProfile(newProfile);
            } catch (createErr) {
              handleFirestoreError(createErr, OperationType.CREATE, profilePath);
            }
          }
        } catch (getErr) {
          handleFirestoreError(getErr, OperationType.GET, profilePath);
        }
      } else {
        setProfile(null);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const [authError, setAuthError] = useState<string | null>(null);

  const login = async (providerType: 'github' | 'google' = 'github') => {
    setAuthError(null);
    try {
      if (providerType === 'github') {
        const githubProvider = new GithubAuthProvider();
        githubProvider.addScope('repo');
        githubProvider.addScope('read:user');
        const result = await signInWithPopup(auth, githubProvider);
        const credential = GithubAuthProvider.credentialFromResult(result);
        if (credential?.accessToken) {
          localStorage.setItem('github_access_token', credential.accessToken);
        }
      } else {
        const googleProvider = new GoogleAuthProvider();
        await signInWithPopup(auth, googleProvider);
      }
    } catch (error: any) {
      if (error.code === 'auth/popup-closed-by-user') {
        return;
      }
      console.error("Login Error:", error);
      if (error.code === 'auth/popup-blocked') {
        setAuthError('POPUP_BLOCKED');
      } else if (error.code === 'auth/account-exists-with-different-credential') {
        setAuthError('ACCOUNT_EXISTS_DIFFERENT_CREDENTIAL');
      } else if (error.code === 'auth/operation-not-allowed') {
        setAuthError(`Authentication provider (${providerType}) is not enabled in Firebase Auth settings.`);
      } else if (error.code === 'auth/unauthorized-domain') {
        setAuthError('Domain unauthorized in Firebase Auth. Try opening the app in a new tab.');
      } else {
        setAuthError(error.message || 'Authentication failed. Please try again.');
      }
    }
  };

  const logout = () => {
    localStorage.removeItem('github_access_token');
    signOut(auth);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#f4f7fa] text-slate-800 font-sans flex flex-col items-center justify-center p-6 text-center">
        <div className="bg-white border border-slate-200 p-8 rounded-xl max-w-sm w-full space-y-4 shadow-md">
          <motion.div
            animate={{ opacity: [0.6, 1, 0.6] }}
            transition={{ repeat: Infinity, duration: 1.5 }}
            className="text-center"
          >
            <p className="text-lg font-bold text-[#1976d2] uppercase tracking-wider">CODEGUARD</p>
            <p className="text-xs text-slate-500 mt-1">Authenticating session...</p>
          </motion.div>
          <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden border border-slate-200">
            <motion.div 
              animate={{ x: ['-100%', '100%'] }}
              transition={{ repeat: Infinity, duration: 1.2, ease: "linear" }}
              className="bg-[#1976d2] h-full w-1/3 rounded-full"
            />
          </div>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LandingPage onLogin={login} authError={authError} onClearError={() => setAuthError(null)} />;
  }

  return (
    <div className="min-h-screen bg-[#f4f7fa] text-slate-800 font-sans flex flex-col justify-between selection:bg-[#1976d2] selection:text-white">
      {/* Top Application Header - Clean Material Blue */}
      <header className="bg-[#1976d2] px-6 py-3.5 sticky top-0 z-50 flex items-center justify-between text-white shadow-md">
        <div className="flex items-center gap-6">
          <div 
            onClick={() => { setActiveTab('dashboard'); setSelectedRepoId(null); }}
            className="flex items-center gap-2.5 cursor-pointer group"
          >
            <Github className="w-5 h-5 text-white" />
            <span className="font-bold text-base sm:text-lg tracking-wider text-white uppercase flex items-center gap-2">
              CODEGUARD
            </span>
          </div>
        </div>

        {/* User Status & Account Settings Bar */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowSettingsModal(true)}
            className="flex items-center gap-2 bg-white/10 hover:bg-white/20 border border-white/20 px-3 py-1.5 rounded-lg text-xs transition-colors group cursor-pointer text-white font-medium"
            title="Open Account Settings"
          >
            {profile?.photoURL ? (
              <img src={profile.photoURL} alt="" className="w-5 h-5 rounded-full border border-white/40 object-cover" />
            ) : (
              <div className="w-5 h-5 rounded-full bg-white/20 border border-white/40 flex items-center justify-center text-[10px] font-bold text-white">
                {profile?.displayName?.charAt(0) || user.email?.charAt(0) || 'U'}
              </div>
            )}
            <span className="max-w-[120px] sm:max-w-[180px] truncate">
              {profile?.displayName || user.displayName || user.email?.split('@')[0] || 'Developer'}
            </span>
            <span className="text-white/80 text-[11px] ml-1 uppercase font-semibold">Settings</span>
          </button>
        </div>
      </header>

      {/* Navigation Sub-Bar */}
      <div className="bg-[#f0f4f8] border-b border-slate-200 px-4 sm:px-6 py-1 flex items-center justify-between overflow-x-auto">
        <nav className="flex items-center gap-1 sm:gap-2">
          <NavTab 
            active={activeTab === 'dashboard' && !selectedRepoId} 
            onClick={() => { setActiveTab('dashboard'); setSelectedRepoId(null); }}
            label="Dashboard"
          />
          <NavTab 
            active={activeTab === 'network' || selectedRepoId !== null} 
            onClick={() => setActiveTab('network')}
            label="My Repositories"
            icon={<Github className="w-3.5 h-3.5" />}
          />
          <NavTab 
            active={activeTab === 'decrypt'} 
            onClick={() => setActiveTab('decrypt')}
            label="Security Policies"
          />
          <NavTab 
            active={activeTab === 'terminal'} 
            onClick={() => setActiveTab('terminal')}
            label="CLI Terminal"
            icon={<Terminal className="w-3.5 h-3.5" />}
          />
        </nav>
        <div className="hidden md:flex items-center gap-2 text-[11px] text-slate-500 font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-500" />
          <span>SAST Engine Online</span>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-8">
        <AnimatePresence mode="wait">
          {activeTab === 'dashboard' && (
            <motion.div key="dashboard" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="w-full">
              <Dashboard onRepoSelect={(id) => { setSelectedRepoId(id); setActiveTab('network'); }} />
            </motion.div>
          )}

          {activeTab === 'network' && (
            <motion.div key="network" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="w-full">
              {!selectedRepoId ? (
                <Dashboard onRepoSelect={(id) => setSelectedRepoId(id)} />
              ) : (
                <RepoAudit repoId={selectedRepoId} onBack={() => setSelectedRepoId(null)} />
              )}
            </motion.div>
          )}

          {activeTab === 'decrypt' && (
            <motion.div key="decrypt" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="w-full">
              <PolicyManager />
            </motion.div>
          )}

          {activeTab === 'terminal' && (
            <motion.div key="terminal" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="w-full max-w-5xl mx-auto">
              <TerminalConsole 
                onNavigate={(t) => {
                  if (t === 'network') setActiveTab('network');
                  else if (t === 'decrypt') setActiveTab('decrypt');
                  else if (t === 'dashboard') setActiveTab('dashboard');
                  else setActiveTab('terminal');
                }} 
                onSelectRepo={(id) => { setSelectedRepoId(id); setActiveTab('network'); }} 
              />
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white px-6 py-3.5 text-xs text-slate-500 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <span className="font-medium text-slate-700">User Terms and Policy</span>
        </div>
        <span className="hidden sm:inline text-slate-400">OWASP Top 10 • SAST & PR Automated Remediations</span>
      </footer>

      {/* User Account Settings Popup Modal */}
      <AnimatePresence>
        {showSettingsModal && (
          <UserSettingsModal
            user={user}
            profile={profile}
            onClose={() => setShowSettingsModal(false)}
            onLogout={logout}
            onProfileUpdated={(updatedProfile) => setProfile(updatedProfile)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function NavTab({ active, onClick, label, icon }: { active: boolean; onClick: () => void; label: string; icon?: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-3.5 py-2 rounded-md text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer border-b-2 ${
        active 
          ? 'border-[#1976d2] text-[#1976d2] bg-white shadow-xs' 
          : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
      }`}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}
