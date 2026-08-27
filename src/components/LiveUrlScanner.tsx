import React, { useState } from 'react';
import {
  Globe2,
  LoaderCircle,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Mail,
  Server,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  FileCode,
  Layers,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

type LiveFinding = {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  evidence: string;
  recommendation: string;
  affectedUrl: string;
};

type TlsCertInfo = {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  expired: boolean;
  expiresSoon: boolean;
  sans: string[];
  protocol: string;
  cipher: string;
  authorized: boolean;
  authorizationError?: string;
  serialNumber?: string;
  fingerprint256?: string;
};

type DnsPostureInfo = {
  domain: string;
  spf: {
    configured: boolean;
    raw?: string;
    policy?: 'hardfail (-all)' | 'softfail (~all)' | 'neutral (?all)' | 'permissive (+all)' | 'other';
    isPermissive: boolean;
  };
  dmarc: {
    configured: boolean;
    raw?: string;
    policy?: 'reject' | 'quarantine' | 'none' | 'unknown';
    rua?: string;
  };
  caa: {
    configured: boolean;
    records: string[];
  };
  mx: {
    configured: boolean;
    records: string[];
  };
};

type ScanResult = {
  targetUrl: string;
  pagesCrawled: number;
  crawledUrls: string[];
  techStack: string[];
  findings: LiveFinding[];
  score: number;
  scanDuration: number;
  sensitivePaths: { path: string; status: number; accessible: boolean }[];
  tlsCert?: TlsCertInfo | null;
  dnsPosture?: DnsPostureInfo | null;
};

const severityStyle: Record<LiveFinding['severity'], string> = {
  critical: 'bg-red-100 border-red-300 text-red-800',
  high: 'bg-red-50 border-red-200 text-red-700',
  medium: 'bg-amber-50 border-amber-200 text-amber-700',
  low: 'bg-blue-50 border-blue-200 text-blue-700',
  info: 'bg-slate-50 border-slate-200 text-slate-600',
};

export function LiveUrlScanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [showCrawledUrls, setShowCrawledUrls] = useState(false);

  const scan = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setResult(null);
    setSelectedCategory('all');
    let target = url.trim();
    if (target && !/^https?:\/\//i.test(target)) target = `https://${target}`;
    setLoading(true);
    try {
      const response = await fetch('/api/live-crawl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Live scan could not be completed.');
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Live scan could not be completed.');
    } finally {
      setLoading(false);
    }
  };

  const categories = result
    ? ['all', ...Array.from(new Set(result.findings.map((f) => f.category)))]
    : [];

  const filteredFindings = result
    ? selectedCategory === 'all'
      ? result.findings
      : result.findings.filter((f) => f.category === selectedCategory)
    : [];

  return (
    <div className="space-y-4 font-sans">
      {/* Target URL Input Form */}
      <form onSubmit={scan} className="space-y-3 rounded-xl border border-slate-200 bg-white p-4 shadow-xs">
        <div className="flex items-center justify-between">
          <label className="text-xs font-semibold text-slate-900">
            Public Website or Domain
          </label>
          <span className="text-[11px] text-slate-400">TLS, DNS Posture, Headers & Endpoints</span>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
            placeholder="https://app.example.com or example.com"
            inputMode="url"
            className="min-w-0 flex-1 rounded-lg border border-slate-200 bg-slate-50/50 px-3.5 py-2 font-mono text-xs text-slate-800 outline-none transition-colors focus:border-slate-400 focus:bg-white"
          />
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-slate-950 px-4 py-2 text-xs font-medium text-white shadow-xs transition-colors hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="h-3.5 w-3.5" />}
            <span>{loading ? 'Auditing Target…' : 'Scan URL'}</span>
          </button>
        </div>
        <p className="text-[11px] text-slate-400">
          Private IP ranges and localhost are blocked for safety.
        </p>
      </form>

      {error && (
        <div className="flex items-center gap-2.5 rounded-lg border border-red-200 bg-red-50 p-3.5 text-xs text-red-700">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="space-y-5">
          {/* Header Summary Banner */}
          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xs">
            <div className="flex flex-col gap-2 border-b border-slate-200 bg-slate-50 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Target Assessed</p>
                <p className="truncate font-mono text-xs font-semibold text-slate-800">{result.targetUrl}</p>
              </div>
              <div className="flex items-center gap-3">
                <span
                  className={`w-fit rounded-md border px-2.5 py-1 font-mono text-xs font-bold ${
                    result.score >= 90
                      ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                      : result.score >= 70
                      ? 'border-amber-200 bg-amber-50 text-amber-700'
                      : 'border-red-200 bg-red-50 text-red-700'
                  }`}
                >
                  POSTURE SCORE {result.score}/100
                </span>
              </div>
            </div>

            {/* Quick Metrics */}
            <div className="grid grid-cols-2 gap-px border-b border-slate-200 bg-slate-200 sm:grid-cols-4">
              <div className="bg-white p-3.5">
                <p className="text-[10px] font-bold uppercase text-slate-400">Pages Crawled</p>
                <p className="mt-1 font-mono text-base font-bold text-slate-800">{result.pagesCrawled}</p>
              </div>
              <div className="bg-white p-3.5">
                <p className="text-[10px] font-bold uppercase text-slate-400">Total Findings</p>
                <p className="mt-1 font-mono text-base font-bold text-slate-800">{result.findings.length}</p>
              </div>
              <div className="bg-white p-3.5">
                <p className="text-[10px] font-bold uppercase text-slate-400">Exposed Endpoints</p>
                <p className="mt-1 font-mono text-base font-bold text-slate-800">
                  {result.sensitivePaths.filter((path) => path.accessible).length}
                </p>
              </div>
              <div className="bg-white p-3.5">
                <p className="text-[10px] font-bold uppercase text-slate-400">Scan Duration</p>
                <p className="mt-1 font-mono text-base font-bold text-slate-800">{result.scanDuration}s</p>
              </div>
            </div>

            {/* Tech Stack Bar */}
            {result.techStack.length > 0 && (
              <div className="border-b border-slate-200 px-5 py-3 bg-slate-50/50">
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Detected Technology & Infrastructure
                </p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {result.techStack.map((tech) => (
                    <span
                      key={tech}
                      className="rounded border border-slate-200 bg-white px-2 py-0.5 font-mono text-[10px] font-medium text-slate-700 shadow-2xs"
                    >
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* TLS Certificate & DNS Posture Grid */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {/* TLS / Certificate Card */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
              <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                <div className="flex items-center gap-2">
                  <div className="rounded-md bg-blue-50 p-1.5 text-[#1976d2]">
                    <Lock className="h-4 w-4" />
                  </div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">TLS & Certificate Health</h4>
                </div>
                {result.tlsCert ? (
                  <span
                    className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${
                      result.tlsCert.expired
                        ? 'border border-red-200 bg-red-50 text-red-700'
                        : result.tlsCert.expiresSoon
                        ? 'border border-amber-200 bg-amber-50 text-amber-700'
                        : 'border border-emerald-200 bg-emerald-50 text-emerald-700'
                    }`}
                  >
                    {result.tlsCert.expired
                      ? 'Expired'
                      : result.tlsCert.expiresSoon
                      ? `Expires in ${result.tlsCert.daysRemaining}d`
                      : `Valid (${result.tlsCert.daysRemaining}d remaining)`}
                  </span>
                ) : (
                  <span className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] text-slate-500">
                    No TLS Detected
                  </span>
                )}
              </div>

              {result.tlsCert ? (
                <div className="space-y-2 text-xs">
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div>
                      <span className="text-slate-400">Issuer:</span>{' '}
                      <span className="font-semibold text-slate-800">{result.tlsCert.issuer}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Subject:</span>{' '}
                      <span className="font-mono text-slate-800">{result.tlsCert.subject}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Protocol:</span>{' '}
                      <span className="font-mono font-medium text-slate-800">{result.tlsCert.protocol}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Validation:</span>{' '}
                      <span
                        className={`font-semibold ${
                          result.tlsCert.authorized ? 'text-emerald-700' : 'text-red-700'
                        }`}
                      >
                        {result.tlsCert.authorized ? 'CA Authorized' : result.tlsCert.authorizationError || 'Untrusted'}
                      </span>
                    </div>
                  </div>

                  {result.tlsCert.sans && result.tlsCert.sans.length > 0 && (
                    <div className="pt-1.5 border-t border-slate-100">
                      <span className="text-[10px] font-bold uppercase text-slate-400">SAN Coverage ({result.tlsCert.sans.length}):</span>
                      <div className="mt-1 flex flex-wrap gap-1 max-h-16 overflow-y-auto">
                        {result.tlsCert.sans.slice(0, 6).map((san) => (
                          <span key={san} className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[9px] text-slate-600">
                            {san}
                          </span>
                        ))}
                        {result.tlsCert.sans.length > 6 && (
                          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[9px] text-slate-500">
                            +{result.tlsCert.sans.length - 6} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-xs text-slate-500">Target host did not present a valid TLS certificate on port 443.</p>
              )}
            </div>

            {/* DNS & Email Security Posture Card */}
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
              <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                <div className="flex items-center gap-2">
                  <div className="rounded-md bg-blue-50 p-1.5 text-[#1976d2]">
                    <Mail className="h-4 w-4" />
                  </div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">DNS & Email Defense Posture</h4>
                </div>
                <span className="text-[10px] text-slate-400 font-mono">
                  {result.dnsPosture?.domain || 'DNS'}
                </span>
              </div>

              {result.dnsPosture ? (
                <div className="space-y-2.5 text-xs">
                  {/* SPF */}
                  <div className="flex items-center justify-between">
                    <span className="text-slate-600 font-medium">SPF Record</span>
                    {result.dnsPosture.spf.configured ? (
                      <span
                        className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
                          result.dnsPosture.spf.isPermissive
                            ? 'border border-red-200 bg-red-50 text-red-700'
                            : 'border border-emerald-200 bg-emerald-50 text-emerald-700'
                        }`}
                      >
                        {result.dnsPosture.spf.policy || 'Configured'}
                      </span>
                    ) : (
                      <span className="rounded border border-amber-200 bg-amber-50 px-2 py-0.5 font-mono text-[10px] font-bold text-amber-700">
                        Missing
                      </span>
                    )}
                  </div>

                  {/* DMARC */}
                  <div className="flex items-center justify-between">
                    <span className="text-slate-600 font-medium">DMARC Policy</span>
                    {result.dnsPosture.dmarc.configured ? (
                      <span
                        className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
                          result.dnsPosture.dmarc.policy === 'reject' || result.dnsPosture.dmarc.policy === 'quarantine'
                            ? 'border border-emerald-200 bg-emerald-50 text-emerald-700'
                            : 'border border-amber-200 bg-amber-50 text-amber-700'
                        }`}
                      >
                        p={result.dnsPosture.dmarc.policy || 'none'}
                      </span>
                    ) : (
                      <span className="rounded border border-amber-200 bg-amber-50 px-2 py-0.5 font-mono text-[10px] font-bold text-amber-700">
                        Missing
                      </span>
                    )}
                  </div>

                  {/* CAA */}
                  <div className="flex items-center justify-between">
                    <span className="text-slate-600 font-medium">CAA Records</span>
                    {result.dnsPosture.caa.configured ? (
                      <span className="rounded border border-emerald-200 bg-emerald-50 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-700">
                        {result.dnsPosture.caa.records.length} Authorized
                      </span>
                    ) : (
                      <span className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5 font-mono text-[10px] font-medium text-slate-500">
                        Not Configured
                      </span>
                    )}
                  </div>

                  {/* MX */}
                  <div className="flex items-center justify-between">
                    <span className="text-slate-600 font-medium">Mail Exchange (MX)</span>
                    <span className="font-mono text-[10px] text-slate-600">
                      {result.dnsPosture.mx.configured
                        ? `${result.dnsPosture.mx.records.length} servers active`
                        : 'None detected'}
                    </span>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-500">DNS posture records could not be resolved for this host.</p>
              )}
            </div>
          </div>

          {/* Exposed Endpoints & Crawled Links Toggle */}
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-slate-600" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  Endpoint & Sensitive Path Probes
                </h4>
              </div>
              <button
                type="button"
                onClick={() => setShowCrawledUrls(!showCrawledUrls)}
                className="flex items-center gap-1 text-[11px] font-semibold text-[#1976d2] hover:underline"
              >
                <span>{showCrawledUrls ? 'Hide Crawled URLs' : `View Crawled URLs (${result.crawledUrls.length})`}</span>
                {showCrawledUrls ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              </button>
            </div>

            {showCrawledUrls && (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 max-h-32 overflow-y-auto space-y-1">
                {result.crawledUrls.map((href) => (
                  <p key={href} className="truncate font-mono text-[10px] text-slate-600">
                    {href}
                  </p>
                ))}
              </div>
            )}

            {result.sensitivePaths.length > 0 ? (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {result.sensitivePaths.map((p) => (
                  <div
                    key={p.path}
                    className={`flex items-center justify-between rounded-lg border p-2 text-xs font-mono ${
                      p.accessible
                        ? 'border-red-200 bg-red-50 text-red-800'
                        : 'border-slate-200 bg-slate-50 text-slate-600'
                    }`}
                  >
                    <span className="truncate">{p.path}</span>
                    <span className="ml-1 text-[10px] font-bold">
                      {p.accessible ? 'EXPOSED' : `HTTP ${p.status}`}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500">No sensitive endpoints or exposed files were detected.</p>
            )}
          </div>

          {/* Vulnerability & Posture Findings */}
          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xs">
            <div className="flex flex-col gap-3 border-b border-slate-200 bg-slate-50 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  Security Findings ({filteredFindings.length})
                </h4>
                <p className="text-[11px] text-slate-500">Actionable remediation guidance prioritized by severity.</p>
              </div>

              {/* Category Filter Pills */}
              {categories.length > 2 && (
                <div className="flex flex-wrap gap-1">
                  {categories.map((cat) => (
                    <button
                      key={cat}
                      onClick={() => setSelectedCategory(cat)}
                      className={`rounded-md px-2.5 py-1 text-[10px] font-bold uppercase transition-colors ${
                        selectedCategory === cat
                          ? 'bg-[#1976d2] text-white shadow-2xs'
                          : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-100'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {filteredFindings.length === 0 ? (
              <div className="flex gap-3 p-6 text-xs text-emerald-700">
                <ShieldCheck className="h-5 w-5 shrink-0" />
                <div>
                  <p className="font-bold">No issues observed in this category.</p>
                  <p className="text-slate-500 mt-0.5">
                    Continuous monitoring and automated regression tests are recommended.
                  </p>
                </div>
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {filteredFindings.map((finding) => (
                  <div key={`${finding.id}-${finding.affectedUrl}`} className="p-4 hover:bg-slate-50/50 transition-colors">
                    <div className="flex items-start gap-3">
                      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" />
                      <div className="min-w-0 flex-1 space-y-1.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <h5 className="text-xs font-bold text-slate-900">{finding.title}</h5>
                          <span
                            className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                              severityStyle[finding.severity]
                            }`}
                          >
                            {finding.severity}
                          </span>
                          <span className="font-mono text-[10px] text-slate-400">
                            {finding.category} · {finding.id}
                          </span>
                        </div>
                        <p className="text-xs text-slate-600 leading-relaxed">
                          <span className="font-semibold text-slate-800">Evidence:</span> {finding.evidence}
                        </p>
                        <p className="text-xs text-slate-600 leading-relaxed">
                          <span className="font-semibold text-slate-800">Remediation:</span> {finding.recommendation}
                        </p>
                        <p className="font-mono text-[10px] text-slate-400 truncate">{finding.affectedUrl}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
