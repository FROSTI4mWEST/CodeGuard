import React from 'react';
import { motion } from 'motion/react';
import { Github, Chrome, Terminal } from 'lucide-react';

interface LandingPageProps {
  onLogin: (provider: 'github' | 'google') => void;
  authError: string | null;
  onClearError?: () => void;
}

export function LandingPage({ onLogin, authError, onClearError }: LandingPageProps) {
  const openInNewTab = () => {
    window.open(window.location.href, '_blank');
  };

  return (
    <div className="min-h-screen bg-[#f4f7fa] text-slate-800 font-sans flex flex-col justify-between selection:bg-[#1976d2] selection:text-white">
      {/* Navigation Header */}
      <header className="bg-[#1976d2] px-6 py-4 sticky top-0 z-50 flex items-center justify-between text-white shadow-md">
        <div className="flex items-center gap-3">
          <span className="font-bold text-lg tracking-wider text-white uppercase flex items-center gap-2">
            CodeGuard <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-white/20 text-white uppercase">v1.0</span>
          </span>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => onLogin('github')}
            className="bg-white hover:bg-slate-100 text-[#1976d2] font-bold px-3.5 py-1.5 rounded-lg text-xs transition-all flex items-center gap-2 shadow-xs cursor-pointer"
          >
            <Github className="w-4 h-4" />
            <span>GITHUB LOGIN</span>
          </button>
          <button
            onClick={() => onLogin('google')}
            className="border border-white/40 hover:bg-white/10 text-white font-semibold px-3.5 py-1.5 rounded-lg text-xs transition-all flex items-center gap-2 cursor-pointer"
          >
            <Chrome className="w-4 h-4" />
            <span>GOOGLE</span>
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <main className="my-auto py-16 px-6 max-w-5xl mx-auto text-center space-y-10">
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="space-y-6"
        >
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-blue-200 bg-blue-50 text-xs font-semibold text-[#1976d2] uppercase tracking-wider">
            <Terminal className="w-3.5 h-3.5" />
            <span>AUTOMATED CODE SECURITY & VULNERABILITY AUDITING</span>
          </div>

          <h1 className="text-4xl sm:text-6xl md:text-7xl font-extrabold tracking-tight text-slate-900 leading-tight">
            Automated Code Auditing & <br className="hidden sm:block" />
            <span className="text-[#1976d2]">
              Repository Security
            </span>
          </h1>

          <p className="max-w-2xl mx-auto text-base sm:text-lg text-slate-600 leading-relaxed">
            Continuous vulnerability scanning for your GitHub repositories. Detect security flaws, enforce OWASP compliance, and generate automated pull request fixes.
          </p>
        </motion.div>

        {/* Error / Popup Blocked Alert Box */}
        {authError && (
          <motion.div 
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="border border-red-200 bg-red-50 rounded-xl p-5 text-left max-w-xl mx-auto space-y-3"
          >
            <div className="flex items-center gap-3 text-red-700">
              <h3 className="font-bold text-xs uppercase tracking-wider">
                {authError === 'POPUP_BLOCKED' 
                  ? 'AUTHENTICATION POPUP BLOCKED' 
                  : authError === 'ACCOUNT_EXISTS_DIFFERENT_CREDENTIAL'
                  ? 'ACCOUNT EXISTS WITH DIFFERENT PROVIDER'
                  : 'AUTHENTICATION NOTICE'}
              </h3>
            </div>
            
            <p className="text-xs text-red-600 leading-relaxed">
              {authError === 'POPUP_BLOCKED' 
                ? 'Your browser or iframe preview blocked the GitHub authentication popup. Please click below to open CodeGuard in a new tab to complete sign in.' 
                : authError === 'ACCOUNT_EXISTS_DIFFERENT_CREDENTIAL'
                ? 'An account already exists with the email linked to your GitHub account using Google or Email login. Please sign in with Google or enable "Allow multiple accounts with the same email" in your Firebase Console Settings.'
                : authError}
            </p>

            <div className="flex flex-wrap gap-3 pt-2">
              {authError === 'ACCOUNT_EXISTS_DIFFERENT_CREDENTIAL' ? (
                <button
                  onClick={() => { onClearError?.(); onLogin('google'); }}
                  className="bg-[#1976d2] text-white font-bold px-4 py-2 rounded-lg text-xs uppercase flex items-center gap-2 hover:bg-[#1565c0] transition-colors cursor-pointer shadow-xs"
                >
                  <Chrome className="w-4 h-4" />
                  <span>Sign In With Google</span>
                </button>
              ) : (
                <button
                  onClick={openInNewTab}
                  className="bg-red-600 text-white font-bold px-4 py-2 rounded-lg text-xs uppercase flex items-center gap-2 hover:bg-red-700 transition-colors cursor-pointer shadow-xs"
                >
                  <span>Open App in New Tab</span>
                </button>
              )}
              {onClearError && (
                <button
                  onClick={onClearError}
                  className="border border-slate-300 bg-white text-slate-700 font-medium px-4 py-2 rounded-lg text-xs uppercase hover:bg-slate-50 transition-colors cursor-pointer"
                >
                  Dismiss
                </button>
              )}
            </div>
          </motion.div>
        )}

        {/* Primary CTA */}
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-2"
        >
          <button
            onClick={() => onLogin('github')}
            className="w-full sm:w-auto bg-[#1976d2] hover:bg-[#1565c0] text-white font-bold py-3.5 px-7 rounded-xl text-sm flex items-center justify-center gap-2.5 shadow-md transition-all cursor-pointer"
          >
            <Github className="w-5 h-5" />
            <span>CONNECT WITH GITHUB</span>
          </button>
          <button
            onClick={() => onLogin('google')}
            className="w-full sm:w-auto bg-white hover:bg-slate-50 text-slate-800 font-bold py-3.5 px-6 rounded-xl text-sm flex items-center justify-center gap-2 border border-slate-300 shadow-xs transition-all cursor-pointer"
          >
            <Chrome className="w-5 h-5" />
            <span>CONNECT WITH GOOGLE</span>
          </button>
        </motion.div>

        {/* Mock Code Preview Box */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="border border-slate-200 bg-white rounded-xl shadow-md overflow-hidden text-left max-w-3xl mx-auto font-mono text-xs"
        >
          <div className="bg-[#f8fafc] px-4 py-3 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-400" />
              <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
              <Terminal className="w-3.5 h-3.5 text-slate-500 ml-1" />
              <span className="text-slate-600 text-[11px]">codeguard-scan-report.json</span>
            </div>
            <span className="text-emerald-600 font-bold text-[10px] uppercase">STATUS: ACTIVE</span>
          </div>

          <div className="p-5 space-y-3 bg-white leading-relaxed text-slate-800">
            <div className="text-red-600 font-bold">
              CRITICAL: Unsanitized input in API route `/api/query` (CWE-89 SQL Injection)
            </div>
            <p className="text-slate-500 text-[11px]">
              Source file: <span className="text-[#1976d2] font-semibold underline">src/routes/search.ts:42</span> — User parameters passed directly to SQL query string.
            </p>
            <div className="bg-slate-900 text-slate-100 rounded-lg p-3 text-[11px] space-y-1">
              <p className="text-slate-400">// CodeGuard Automated Patch Recommendation:</p>
              <p className="text-red-400">{`- const result = await db.query(\`SELECT * FROM users WHERE id = '\${req.query.id}'\`);`}</p>
              <p className="text-emerald-400">{`+ const result = await db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);`}</p>
            </div>
          </div>
        </motion.div>

        {/* Feature Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-6 text-left">
          <div className="border border-slate-200 bg-white p-6 rounded-xl space-y-2 shadow-xs hover:border-[#1976d2] transition-colors">
            <h3 className="font-bold text-slate-900 text-base">Automated SAST Scanning</h3>
            <p className="text-slate-600 text-xs leading-relaxed">
              Scan source code and dependency manifests against OWASP standards, CWE patterns, and known security flaws.
            </p>
          </div>

          <div className="border border-slate-200 bg-white p-6 rounded-xl space-y-2 shadow-xs hover:border-[#1976d2] transition-colors">
            <h3 className="font-bold text-slate-900 text-base">One-Click PR Fixes</h3>
            <p className="text-slate-600 text-xs leading-relaxed">
              Generate precise code remediation patches and automatically push Pull Requests directly to your GitHub repository.
            </p>
          </div>

          <div className="border border-slate-200 bg-white p-6 rounded-xl space-y-2 shadow-xs hover:border-[#1976d2] transition-colors">
            <h3 className="font-bold text-slate-900 text-base">Security Policy Rules</h3>
            <p className="text-slate-600 text-xs leading-relaxed">
              Define custom compliance policies, track repository health scores, and enforce CI/CD guardrails.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white px-6 py-4 text-xs text-slate-500 flex flex-col sm:flex-row justify-between items-center gap-2">
        <div>
          <span className="font-bold text-slate-800">User Terms and Policy</span>
        </div>
        <span className="text-[11px] text-slate-400">Continuous Repository Vulnerability Auditing</span>
      </footer>
    </div>
  );
}
