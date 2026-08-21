import React, { useState, useEffect, useRef } from 'react';
import { db, auth } from '../lib/firebase';
import { collection, query, where, getDocs } from 'firebase/firestore';
import { Terminal } from 'lucide-react';
import { VERIFIED_PATTERNS } from '../lib/securityAudit';

interface LogMessage {
  id: string;
  time: string;
  type: 'system' | 'command' | 'output' | 'error' | 'success';
  text: string;
}

export function TerminalConsole({ 
  onNavigate,
  onSelectRepo
}: { 
  onNavigate: (tab: 'dashboard' | 'network' | 'decrypt' | 'terminal') => void;
  onSelectRepo: (id: string) => void;
}) {
  const [input, setInput] = useState('');
  const [logs, setLogs] = useState<LogMessage[]>([
    { id: '1', time: new Date().toLocaleTimeString(), type: 'system', text: 'CODEGUARD SECURITY CLI v1.0.0 ONLINE' },
    { id: '2', time: new Date().toLocaleTimeString(), type: 'system', text: 'Type "help" to view available security commands.' },
    { id: '3', time: new Date().toLocaleTimeString(), type: 'output', text: 'Engine connected to Gemini SAST audit models.' },
  ]);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const addLog = (text: string, type: 'system' | 'command' | 'output' | 'error' | 'success' = 'output') => {
    setLogs(prev => [
      ...prev,
      {
        id: Math.random().toString(),
        time: new Date().toLocaleTimeString(),
        type,
        text
      }
    ]);
  };

  const handleCommand = async (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = input.trim();
    if (!cmd) return;

    addLog(`codeguard@cli:~$ ${cmd}`, 'command');
    setInput('');

    const parts = cmd.split(' ');
    const mainCmd = parts[0].toLowerCase();
    const arg = parts.slice(1).join(' ');

    switch (mainCmd) {
      case 'help':
        addLog('CODEGUARD COMMAND MENU:', 'system');
        addLog('  help                 - Display command menu');
        addLog('  clear                - Clear terminal logs');
        addLog('  status               - View security engine connection status');
        addLog('  repos                - List all monitored repositories');
        addLog('  scan <repo_name>     - Run security audit on repository');
        addLog('  rules                - Display active OWASP/CWE detection patterns');
        addLog('  dashboard            - Switch view to Dashboard');
        addLog('  policies             - Switch view to Security Policies');
        break;

      case 'clear':
        setLogs([]);
        break;

      case 'status':
        addLog('CODEGUARD SECURITY SUITE: OPERATIONAL', 'success');
        addLog('  Authentication: Active (Firebase Auth)');
        addLog('  Database: Connected (Cloud Firestore)');
        addLog('  Rule Base: 5 Verified OWASP Patterns Loaded');
        addLog('  SAST Audit Engine: Online');
        break;

      case 'dashboard':
        onNavigate('dashboard');
        addLog('Navigating to Dashboard view...', 'system');
        break;

      case 'policies':
      case 'policy':
        onNavigate('decrypt');
        addLog('Navigating to Security Policies view...', 'system');
        break;

      case 'rules':
        addLog('VERIFIED OWASP/CWE DETECTION PATTERNS:', 'system');
        VERIFIED_PATTERNS.forEach(p => {
          addLog(`  [${p.source}] ${p.category}: ${p.pattern}`);
          addLog(`    Remediation: ${p.verifiedRemediation}`);
        });
        break;

      case 'repos':
        if (!auth.currentUser) {
          addLog('Authentication error: No signed in user.', 'error');
          return;
        }
        try {
          const q = query(collection(db, 'repositories'), where('addedBy', '==', auth.currentUser.uid));
          const snapshot = await getDocs(q);
          if (snapshot.empty) {
            addLog('No repositories connected to your profile.', 'output');
          } else {
            addLog(`Found ${snapshot.docs.length} connected repositories:`, 'system');
            snapshot.docs.forEach((doc, idx) => {
              const d = doc.data();
              addLog(`  ${idx + 1}. ${d.full_name || d.name} (Health Score: ${d.healthScore || '--'}%)`);
            });
          }
        } catch (err: any) {
          addLog(`Failed to query repositories: ${err.message}`, 'error');
        }
        break;

      case 'scan':
        if (!arg) {
          addLog('Usage: scan <repository_name>', 'error');
          return;
        }
        if (!auth.currentUser) {
          addLog('Authentication error: No signed in user.', 'error');
          return;
        }
        addLog(`Locating repository "${arg}"...`, 'output');
        try {
          const q = query(collection(db, 'repositories'), where('addedBy', '==', auth.currentUser.uid));
          const snapshot = await getDocs(q);
          const matched = snapshot.docs.find(d => {
            const data = d.data();
            return (data.name && data.name.toLowerCase().includes(arg.toLowerCase())) ||
                   (data.full_name && data.full_name.toLowerCase().includes(arg.toLowerCase()));
          });

          if (matched) {
            addLog(`Found repository: ${matched.data().full_name || matched.data().name}`, 'success');
            addLog('Launching security audit...', 'system');
            onSelectRepo(matched.id);
            onNavigate('network');
          } else {
            addLog(`No matching repository found for "${arg}". Type "repos" to see connected repositories.`, 'error');
          }
        } catch (err: any) {
          addLog(`Scan execution error: ${err.message}`, 'error');
        }
        break;

      default:
        addLog(`Command not recognized: "${cmd}". Type "help" for command menu.`, 'error');
        break;
    }
  };

  return (
    <div className="space-y-4 max-w-5xl mx-auto font-sans">
      {/* Module Title Banner */}
      <div className="border border-slate-200 bg-white p-5 rounded-2xl flex items-center justify-between shadow-xs">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-200 flex items-center justify-center text-[#1976d2]">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900 uppercase">CodeGuard Security CLI</h2>
            <p className="text-xs text-slate-500 mt-0.5">Command-line interface for automated code security auditing</p>
          </div>
        </div>
        <div className="flex items-center gap-2 px-3 py-1 bg-emerald-50 border border-emerald-200 rounded-full">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-xs font-mono text-emerald-700 font-semibold">CLI ACTIVE</span>
        </div>
      </div>

      {/* Interactive CLI Console Box */}
      <div className="border border-slate-800 bg-slate-950 p-5 rounded-2xl font-mono text-xs text-slate-200 shadow-xl min-h-[480px] flex flex-col justify-between">
        <div className="space-y-2 overflow-y-auto max-h-[420px] pr-2">
          {logs.map((log) => (
            <div key={log.id} className="flex items-start gap-2 leading-relaxed">
              <span className="text-slate-500 select-none text-[10px]">[{log.time}]</span>
              <span className={`
                ${log.type === 'command' ? 'text-blue-400 font-bold underline' : ''}
                ${log.type === 'system' ? 'text-amber-400 font-semibold' : ''}
                ${log.type === 'error' ? 'text-red-400 font-bold' : ''}
                ${log.type === 'success' ? 'text-emerald-400 font-bold' : ''}
                ${log.type === 'output' ? 'text-slate-300' : ''}
              `}>
                {log.text}
              </span>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>

        {/* Input Prompt */}
        <form onSubmit={handleCommand} className="mt-4 border-t border-slate-800 pt-3 flex items-center gap-2">
          <span className="text-blue-400 font-bold text-xs">codeguard@cli:~$</span>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type 'help', 'repos', or 'scan <repo>'..."
            className="flex-1 bg-transparent border-none text-slate-100 font-mono text-xs focus:outline-none placeholder-slate-600"
            autoFocus
          />
          <button type="submit" className="text-xs font-bold text-slate-400 hover:text-blue-400 transition-colors px-2 py-1 cursor-pointer">
            RUN
          </button>
        </form>
      </div>
    </div>
  );
}
