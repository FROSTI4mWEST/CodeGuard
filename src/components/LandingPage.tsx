import React from 'react';
import { motion } from 'motion/react';
import { Github, Chrome, Shield, Terminal, ArrowRight, Lock, FileCode, Zap } from 'lucide-react';

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
    <div className="min-h-screen bg-white text-slate-900 font-sans flex flex-col justify-between selection:bg-slate-900 selection:text-white">
      {/* Top Navbar */}
      <header className="sticky top-0 z-50 border-b border-slate-200 bg-white/95 backdrop-blur-md px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <Shield className="h-5 w-5 text-slate-950" />
          <span className="font-semibold text-base tracking-tight text-slate-950">
            CodeGuard
          </span>
          <span className="rounded-md border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[11px] font-medium text-slate-600">
            v2.0
          </span>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => onLogin('google')}
            className="hidden sm:inline-flex items-center gap-2 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 shadow-2xs hover:bg-slate-50 transition-colors cursor-pointer"
          >
            <Chrome className="h-3.5 w-3.5 text-slate-700" />
            <span>Google</span>
          </button>
          <button
            onClick={() => onLogin('github')}
            className="inline-flex items-center gap-2 rounded-md bg-slate-950 px-3.5 py-1.5 text-xs font-medium text-white shadow-xs hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <Github className="h-3.5 w-3.5" />
            <span>Sign in with GitHub</span>
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="my-auto py-16 px-6 max-w-5xl mx-auto text-center space-y-10">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="space-y-4"
        >
          <h1 className="text-4xl sm:text-6xl font-bold tracking-tight text-slate-950 max-w-3xl mx-auto leading-[1.12]">
            Find vulnerabilities before they reach production.
          </h1>

          <p className="max-w-2xl mx-auto text-base sm:text-lg text-slate-600 leading-relaxed font-normal">
            Continuous security scanning for your GitHub repositories and public websites. Identifies security risks in plain English and suggests 1-click code fixes.
          </p>
        </motion.div>

        {/* Auth Error Banner */}
        {authError && (
          <motion.div 
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="border border-slate-300 bg-slate-50 rounded-lg p-4 text-left max-w-xl mx-auto space-y-2.5 text-xs text-slate-800"
          >
            <div className="font-semibold text-slate-950">
              {authError === 'POPUP_BLOCKED' 
                ? 'Authentication popup was blocked' 
                : authError === 'ACCOUNT_EXISTS_DIFFERENT_CREDENTIAL'
                ? 'Account exists with another login provider'
                : 'Authentication notice'}
            </div>
            
            <p className="text-slate-600 leading-relaxed">
              {authError === 'POPUP_BLOCKED' 
                ? 'Your browser blocked the login popup window. Click below to open CodeGuard in a full tab.' 
                : authError === 'ACCOUNT_EXISTS_DIFFERENT_CREDENTIAL'
                ? 'An account already exists with this email address. Please sign in with Google or your existing login method.'
                : authError}
            </p>

            <div className="flex flex-wrap gap-2 pt-1">
              {authError === 'ACCOUNT_EXISTS_DIFFERENT_CREDENTIAL' ? (
                <button
                  onClick={() => { onClearError?.(); onLogin('google'); }}
                  className="rounded-md bg-slate-950 px-3.5 py-1.5 font-medium text-white text-xs hover:bg-slate-800 transition-colors cursor-pointer"
                >
                  Sign in with Google
                </button>
              ) : (
                <button
                  onClick={openInNewTab}
                  className="rounded-md bg-slate-950 px-3.5 py-1.5 font-medium text-white text-xs hover:bg-slate-800 transition-colors cursor-pointer"
                >
                  Open in New Tab
                </button>
              )}
              {onClearError && (
                <button
                  onClick={onClearError}
                  className="rounded-md border border-slate-200 bg-white px-3 py-1.5 font-medium text-slate-700 text-xs hover:bg-slate-50 transition-colors cursor-pointer"
                >
                  Dismiss
                </button>
              )}
            </div>
          </motion.div>
        )}

        {/* Primary Action Buttons */}
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-1"
        >
          <button
            onClick={() => onLogin('github')}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-md bg-slate-950 px-6 py-2.5 text-sm font-medium text-white shadow-xs hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <Github className="w-4 h-4" />
            <span>Connect with GitHub</span>
            <ArrowRight className="w-4 h-4 text-slate-400" />
          </button>
          <button
            onClick={() => onLogin('google')}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-md border border-slate-200 bg-white px-5 py-2.5 text-sm font-medium text-slate-800 shadow-2xs hover:bg-slate-50 transition-colors cursor-pointer"
          >
            <Chrome className="w-4 h-4 text-slate-700" />
            <span>Sign in with Google</span>
          </button>
        </motion.div>

        {/* Minimal Code & Finding Preview */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
          className="border border-slate-200 bg-white rounded-lg shadow-xs overflow-hidden text-left max-w-2xl mx-auto"
        >
          <div className="bg-slate-50 px-4 py-2.5 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono text-xs text-slate-600">
              <Terminal className="w-3.5 h-3.5 text-slate-700" />
              <span>src/routes/search.ts:42</span>
            </div>
            <span className="rounded-md border border-slate-300 bg-slate-100 px-2 py-0.5 text-[10px] font-semibold text-slate-800 uppercase">
              High Severity Finding
            </span>
          </div>

          <div className="p-4 space-y-2 font-sans text-xs">
            <p className="text-slate-950 font-semibold">
              Database query accepts raw user input (SQL Injection risk)
            </p>
            <p className="text-slate-500 text-[11px] leading-relaxed">
              Why this matters: Attackers could send unexpected text to read private database records.
            </p>
            <div className="rounded-md bg-slate-950 p-3 text-slate-100 font-mono space-y-1 overflow-x-auto text-[11px] mt-2">
              <p className="text-slate-400">// Suggested Safe Fix</p>
              <p className="text-slate-400 line-through">{`- const user = await db.query(\`SELECT * FROM users WHERE id = '\${id}'\`);`}</p>
              <p className="text-slate-100">{`+ const user = await db.query('SELECT * FROM users WHERE id = $1', [id]);`}</p>
            </div>
          </div>
        </motion.div>

        {/* Feature Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4 text-left">
          <div className="rounded-lg border border-slate-200 bg-white p-5 space-y-2 shadow-2xs hover:border-slate-300 transition-colors">
            <FileCode className="h-5 w-5 text-slate-950" />
            <h3 className="font-semibold text-slate-950 text-sm">Source Code Auditing</h3>
            <p className="text-slate-600 text-xs leading-relaxed">
              Scans your source files for security risks like hardcoded passwords, dangerous input handling, and outdated packages.
            </p>
          </div>

          <div className="rounded-lg border border-slate-200 bg-white p-5 space-y-2 shadow-2xs hover:border-slate-300 transition-colors">
            <Lock className="h-5 w-5 text-slate-950" />
            <h3 className="font-semibold text-slate-950 text-sm">Live Website & Domain Scan</h3>
            <p className="text-slate-600 text-xs leading-relaxed">
              Audits live URLs for SSL certificate expiration, email spoofing protections (SPF/DMARC), and missing security headers.
            </p>
          </div>

          <div className="rounded-lg border border-slate-200 bg-white p-5 space-y-2 shadow-2xs hover:border-slate-300 transition-colors">
            <Zap className="h-5 w-5 text-slate-950" />
            <h3 className="font-semibold text-slate-950 text-sm">One-Click Fixes</h3>
            <p className="text-slate-600 text-xs leading-relaxed">
              Generates clean, safe code patches and can automatically open a Pull Request on GitHub to fix the issue.
            </p>
          </div>
        </div>
      </main>

      {/* Clean Minimal Footer */}
      <footer className="border-t border-slate-200 bg-white px-6 py-4 text-xs text-slate-500 flex flex-col sm:flex-row justify-between items-center gap-2">
        <div className="flex items-center gap-2">
          <span className="font-medium text-slate-800">CodeGuard</span>
          <span>·</span>
          <span>Security & Code Health Platform</span>
        </div>
        <span className="text-[11px] text-slate-400">All rights reserved</span>
      </footer>
    </div>
  );
}
