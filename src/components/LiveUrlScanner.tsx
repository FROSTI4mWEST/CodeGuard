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

type FindingPresentation = {
  title: string;
  meaning: string;
  fix: string;
};

function getFindingPresentation(finding: LiveFinding): FindingPresentation {
  const presentations: Record<string, FindingPresentation> = {
    'CRAWL-TLS-001': {
      title: 'Visitors are not fully protected while browsing',
      meaning: 'This page uses an unencrypted connection, so information sent between the visitor and the site could be viewed or changed.',
      fix: 'Enable HTTPS, install a valid certificate, and redirect every HTTP request to HTTPS.',
    },
    'CRAWL-HDR-001': {
      title: 'The site is missing a browser safety rule',
      meaning: 'Without this rule, unsafe scripts or content may have more opportunity to run in a visitor’s browser.',
      fix: 'Add a Content-Security-Policy that allows only the scripts, styles, images, and connections your site needs.',
    },
    'CRAWL-HDR-002': {
      title: 'Browsers are not being told to always use HTTPS',
      meaning: 'A visitor could be sent back to an unencrypted version of the site after first visiting securely.',
      fix: 'Add an HSTS response header and configure it for at least one year after confirming HTTPS works everywhere.',
    },
    'CRAWL-HDR-003': {
      title: 'Browsers may guess the wrong file type',
      meaning: 'A browser could interpret a downloaded file as something different from what the site intended.',
      fix: 'Add the X-Content-Type-Options: nosniff header to responses.',
    },
    'CRAWL-HDR-004': {
      title: 'The site may be loadable inside another site',
      meaning: 'An attacker could try to place your page inside an invisible frame and trick someone into clicking it.',
      fix: 'Set a frame-ancestors rule in your Content-Security-Policy or use X-Frame-Options: DENY.',
    },
    'CRAWL-HDR-005': {
      title: 'Links may reveal too much browsing history',
      meaning: 'When visitors follow links away from your site, the destination may learn more about the page they came from than necessary.',
      fix: 'Set Referrer-Policy: strict-origin-when-cross-origin.',
    },
    'CRAWL-HDR-006': {
      title: 'Browser features are not restricted',
      meaning: 'The page has not clearly limited features such as the camera, microphone, or location services.',
      fix: 'Add a Permissions-Policy that disables browser features the application does not need.',
    },
    'CRAWL-CORS-001': {
      title: 'Any website may be able to access signed-in responses',
      meaning: 'The server allows every website to request data while also allowing credentials, which can expose private information.',
      fix: 'Allow only trusted website addresses and enable credentials only where they are required.',
    },
    'CRAWL-CORS-002': {
      title: 'The API is open to every website',
      meaning: 'Any website can ask this server for responses. That may be intentional for a public API, but it is risky for private data.',
      fix: 'Replace the wildcard with a list of trusted website addresses unless the API is deliberately public.',
    },
    'CRAWL-COOKIE-001': {
      title: 'A browser cookie can travel over an unsafe connection',
      meaning: 'This cookie is not restricted to secure HTTPS connections, so it may be exposed if HTTP is used.',
      fix: 'Add the Secure flag to the cookie.',
    },
    'CRAWL-COOKIE-002': {
      title: 'Website scripts can read a browser cookie',
      meaning: 'If malicious code runs on the page, it may be able to read this cookie and steal the session.',
      fix: 'Add the HttpOnly flag so client-side JavaScript cannot read the cookie.',
    },
    'CRAWL-COOKIE-003': {
      title: 'A browser cookie has no cross-site sharing rule',
      meaning: 'Other websites may be able to cause this cookie to be sent with their requests, which can help enable unwanted actions.',
      fix: 'Set SameSite=Lax or SameSite=Strict unless the application has a documented cross-site requirement.',
    },
    'CRAWL-MIXED-001': {
      title: 'Some page resources are not using HTTPS',
      meaning: 'This secure page loads one or more images, scripts, or other files over an unencrypted connection.',
      fix: 'Change every listed resource URL to HTTPS and make sure the provider supports secure delivery.',
    },
    'CRAWL-FORM-001': {
      title: 'A form does not have protection against unwanted submissions',
      meaning: 'Another website may be able to trick a signed-in visitor into submitting an action they did not intend to make.',
      fix: 'Add a unique CSRF token to every form that changes data and check it on the server.',
    },
    'CRAWL-FORM-002': {
      title: 'A form sends information without encryption',
      meaning: 'Data entered into this form can be exposed while it travels to the server.',
      fix: 'Change the form destination to an HTTPS URL.',
    },
    'CRAWL-FORM-003': {
      title: 'A password field needs safer browser settings',
      meaning: 'The browser may save or fill this password in situations the application did not intend.',
      fix: 'Use autocomplete="new-password" for new passwords or autocomplete="off" where appropriate.',
    },
    'CRAWL-REDIR-001': {
      title: 'A link may send visitors to an untrusted website',
      meaning: 'An attacker could modify a link so your trusted domain redirects visitors to a harmful page.',
      fix: 'Check redirect destinations on the server against a list of allowed destinations.',
    },
    'CRAWL-DNS-SPF-MISSING': {
      title: 'Anyone could pretend to send email from this domain',
      meaning: 'The domain has not published a list of servers that are allowed to send its email.',
      fix: 'Publish an SPF record listing your real email providers and finish it with a restrictive rule such as -all.',
    },
    'CRAWL-DNS-DMARC-MISSING': {
      title: 'Suspicious email has no handling instructions',
      meaning: 'Receiving mail services are not told what to do when a message pretending to be from this domain fails its checks.',
      fix: 'Publish a DMARC record and start with monitoring, then move to quarantine or reject after legitimate senders are confirmed.',
    },
    'CRAWL-DNS-DMARC-P-NONE': {
      title: 'Suspicious email is only being monitored',
      meaning: 'The domain can see possible email impersonation, but receiving mail services are not asked to block or isolate it.',
      fix: 'After checking reports and confirming legitimate senders, change the policy to quarantine or reject.',
    },
    'CRAWL-DNS-CAA-MISSING': {
      title: 'Any certificate provider may request a certificate',
      meaning: 'The domain does not restrict which certificate companies may create HTTPS certificates for it.',
      fix: 'Add CAA records naming the certificate providers you trust.',
    },
  };

  const presentation = presentations[finding.id];
  if (presentation) return presentation;

  if (finding.category === 'Sensitive Path Exposure') {
    return {
      title: 'A private file or admin area is publicly reachable',
      meaning: 'A path that may contain configuration, source code, backups, or administrative tools can be opened by anyone on the internet.',
      fix: finding.recommendation,
    };
  }
  if (finding.category === 'Outdated Libraries') {
    return {
      title: 'The website uses an older software library',
      meaning: 'Older libraries may contain security problems that attackers already know how to exploit.',
      fix: finding.recommendation,
    };
  }
  if (finding.category === 'TLS / Certificate') {
    return {
      title: 'The website connection certificate needs attention',
      meaning: 'The certificate used to prove this website is trusted, current, and belongs to the correct domain has a problem.',
      fix: finding.recommendation,
    };
  }

  return {
    title: finding.title,
    meaning: finding.evidence,
    fix: finding.recommendation,
  };
}

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
          <span className="text-[11px] text-slate-400">HTTPS, email safety, browser protections & exposed files</span>
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

          {/* Website connection and email safety overview */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {/* TLS / Certificate Card */}
            <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-2xs space-y-3">
              <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                <div className="flex items-center gap-2">
                  <Lock className="h-4 w-4 text-slate-900" />
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-900">Website connection safety</h4>
                </div>
                {result.tlsCert ? (
                  <span
                    className={`rounded-md px-2 py-0.5 font-mono text-[11px] font-medium border ${
                      result.tlsCert.expired
                        ? 'border-red-200 bg-red-50 text-red-800'
                        : result.tlsCert.expiresSoon
                        ? 'border-amber-200 bg-amber-50 text-amber-800'
                        : 'border-slate-200 bg-slate-50 text-slate-800'
                    }`}
                  >
                    {result.tlsCert.expired
                      ? 'Expired'
                      : result.tlsCert.expiresSoon
                      ? `Expires in ${result.tlsCert.daysRemaining}d`
                      : `Valid (${result.tlsCert.daysRemaining}d remaining)`}
                  </span>
                ) : (
                  <span className="rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] text-slate-500">
                    No SSL Detected
                  </span>
                )}
              </div>

              {result.tlsCert ? (
                <div className="space-y-2 text-xs">
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div>
                      <span className="text-slate-400">Issuer:</span>{' '}
                      <span className="font-medium text-slate-900">{result.tlsCert.issuer}</span>
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
                        className={`font-medium ${
                          result.tlsCert.authorized ? 'text-slate-900' : 'text-red-700'
                        }`}
                      >
                        {result.tlsCert.authorized ? 'Trusted Certificate' : result.tlsCert.authorizationError || 'Untrusted'}
                      </span>
                    </div>
                  </div>

                  {result.tlsCert.sans && result.tlsCert.sans.length > 0 && (
                    <div className="pt-1.5 border-t border-slate-100">
                      <span className="text-[10px] font-semibold uppercase text-slate-400">SAN Coverage ({result.tlsCert.sans.length}):</span>
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
                <p className="text-xs text-slate-500">Target host did not present an SSL certificate on port 443.</p>
              )}
            </div>

            {/* DNS & Email Security Posture Card */}
            <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-2xs space-y-3">
              <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                <div className="flex items-center gap-2">
                  <Mail className="h-4 w-4 text-slate-900" />
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-900">Email safety & domain protection</h4>
                </div>
                <span className="text-[10px] text-slate-400 font-mono">
                  {result.dnsPosture?.domain || 'DNS'}
                </span>
              </div>

              {result.dnsPosture ? (
                <div className="space-y-3 text-xs">
                  {/* SPF */}
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <span className="font-medium text-slate-700">Who can send email</span>
                      <p className="mt-0.5 text-[10px] leading-relaxed text-slate-400">
                        Helps stop attackers from sending email that pretends to be from this domain.
                      </p>
                    </div>
                    {result.dnsPosture.spf.configured ? (
                      <span
                        className={`shrink-0 rounded-md border px-2 py-0.5 text-[10px] font-medium ${
                          result.dnsPosture.spf.isPermissive
                            ? 'border-red-200 bg-red-50 text-red-700'
                            : 'border-slate-200 bg-slate-50 text-slate-800'
                        }`}
                        title={`SPF record: ${result.dnsPosture.spf.raw || 'configured'}`}
                      >
                        {result.dnsPosture.spf.isPermissive
                          ? 'Anyone can send'
                          : result.dnsPosture.spf.policy === 'softfail (~all)'
                          ? 'Unverified senders warned'
                          : result.dnsPosture.spf.policy === 'hardfail (-all)'
                          ? 'Unverified senders blocked'
                          : 'Configured'}
                      </span>
                    ) : (
                      <span className="shrink-0 rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-medium text-slate-500">
                        Not configured
                      </span>
                    )}
                  </div>

                  {/* DMARC */}
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <span className="font-medium text-slate-700">Handling of suspicious email</span>
                      <p className="mt-0.5 text-[10px] leading-relaxed text-slate-400">
                        Tells receiving mail services what to do when a message fails the domain checks.
                      </p>
                    </div>
                    {result.dnsPosture.dmarc.configured ? (
                      <span
                        className={`shrink-0 rounded-md border px-2 py-0.5 text-[10px] font-medium ${
                          result.dnsPosture.dmarc.policy === 'none'
                            ? 'border-amber-200 bg-amber-50 text-amber-800'
                            : 'border-slate-200 bg-slate-50 text-slate-800'
                        }`}
                        title={`DMARC policy: p=${result.dnsPosture.dmarc.policy || 'unknown'}`}
                      >
                        {result.dnsPosture.dmarc.policy === 'reject'
                          ? 'Reject suspicious email'
                          : result.dnsPosture.dmarc.policy === 'quarantine'
                          ? 'Send suspicious email to spam'
                          : result.dnsPosture.dmarc.policy === 'none'
                          ? 'Monitor only'
                          : 'Policy configured'}
                      </span>
                    ) : (
                      <span className="shrink-0 rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-medium text-slate-500">
                        Not configured
                      </span>
                    )}
                  </div>

                  {/* CAA */}
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <span className="font-medium text-slate-700">Who can create certificates</span>
                      <p className="mt-0.5 text-[10px] leading-relaxed text-slate-400">
                        Limits which certificate companies can create HTTPS certificates for this domain.
                      </p>
                    </div>
                    {result.dnsPosture.caa.configured ? (
                      <span
                        className="shrink-0 rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-medium text-slate-700"
                        title={`CAA records: ${result.dnsPosture.caa.records.join(', ')}`}
                      >
                        {result.dnsPosture.caa.records.length} allowed
                      </span>
                    ) : (
                      <span className="shrink-0 rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] font-medium text-slate-400">
                        No restriction
                      </span>
                    )}
                  </div>

                  {/* MX */}
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <span className="font-medium text-slate-700">Where domain email goes</span>
                      <p className="mt-0.5 text-[10px] leading-relaxed text-slate-400">
                        Shows the mail services responsible for receiving email for this domain.
                      </p>
                    </div>
                    <span
                      className="shrink-0 text-[10px] text-slate-600"
                      title={`Mail server records: ${result.dnsPosture.mx.records.join(', ') || 'none'}`}
                    >
                      {result.dnsPosture.mx.configured
                        ? `${result.dnsPosture.mx.records.length} configured`
                        : 'Not configured'}
                    </span>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-500">DNS records could not be retrieved for this domain.</p>
              )}
            </div>
          </div>

          {/* Exposed Endpoints & Crawled Links Toggle */}
          <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-2xs space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-slate-900" />
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-900">
                  Endpoint & File Probes
                </h4>
              </div>
              <button
                type="button"
                onClick={() => setShowCrawledUrls(!showCrawledUrls)}
                className="flex items-center gap-1 text-[11px] font-medium text-slate-900 hover:underline cursor-pointer"
              >
                <span>{showCrawledUrls ? 'Hide Crawled URLs' : `View Crawled URLs (${result.crawledUrls.length})`}</span>
                {showCrawledUrls ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              </button>
            </div>

            {showCrawledUrls && (
              <div className="rounded-md border border-slate-200 bg-slate-50 p-3 max-h-32 overflow-y-auto space-y-1">
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
                    className={`flex items-center justify-between rounded-md border p-2 text-xs font-mono ${
                      p.accessible
                        ? 'border-red-200 bg-red-50 text-red-800'
                        : 'border-slate-200 bg-slate-50 text-slate-600'
                    }`}
                  >
                    <span className="truncate">{p.path}</span>
                    <span className="ml-1 text-[10px] font-semibold">
                      {p.accessible ? 'Exposed' : `HTTP ${p.status}`}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500">No sensitive endpoints or exposed files were detected.</p>
            )}
          </div>

          {/* Vulnerability & Posture Findings */}
          <div className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-2xs">
            <div className="flex flex-col gap-3 border-b border-slate-200 bg-slate-50 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-900">
                  Security Findings ({filteredFindings.length})
                </h4>
                <p className="text-[11px] text-slate-500">Clear explanations and recommended fixes.</p>
              </div>

              {/* Category Filter Pills */}
              {categories.length > 2 && (
                <div className="flex flex-wrap gap-1">
                  {categories.map((cat) => (
                    <button
                      key={cat}
                      onClick={() => setSelectedCategory(cat)}
                      className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer border ${
                        selectedCategory === cat
                          ? 'bg-slate-900 text-white border-slate-900 shadow-2xs font-semibold'
                          : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-50'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {filteredFindings.length === 0 ? (
              <div className="flex gap-3 p-6 text-xs text-slate-700">
                <ShieldCheck className="h-5 w-5 shrink-0 text-slate-900" />
                <div>
                  <p className="font-semibold text-slate-900">No security issues observed in this category.</p>
                  <p className="text-slate-500 mt-0.5">
                    Your target passed all external security header and configuration checks.
                  </p>
                </div>
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {filteredFindings.map((finding) => (
                  <div key={`${finding.id}-${finding.affectedUrl}`} className="p-4 hover:bg-slate-50/50 transition-colors">
                    {(() => {
                      const presentation = getFindingPresentation(finding);
                      return (
                    <div className="flex items-start gap-3">
                      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-slate-900" />
                      <div className="min-w-0 flex-1 space-y-1.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <h5 className="text-sm font-semibold text-slate-950">{presentation.title}</h5>
                          <span
                            className="rounded-md border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-slate-700"
                          >
                            {finding.severity}
                          </span>
                          <span className="font-mono text-[10px] text-slate-400">
                            {finding.category}
                          </span>
                        </div>
                        <p className="text-xs text-slate-600 leading-relaxed">
                          <span className="font-semibold text-slate-800">What this means:</span> {presentation.meaning}
                        </p>
                        <p className="text-xs text-slate-600 leading-relaxed">
                          <span className="font-semibold text-slate-800">How to fix it:</span> {presentation.fix}
                        </p>
                        <details className="pt-1">
                          <summary className="cursor-pointer text-[10px] font-medium text-slate-400 hover:text-slate-600">
                            Show technical details
                          </summary>
                          <p className="mt-1 text-[10px] leading-relaxed text-slate-400">
                            {finding.title}: {finding.evidence}
                          </p>
                        </details>
                        <p className="font-mono text-[10px] text-slate-400 truncate">{finding.affectedUrl}</p>
                      </div>
                    </div>
                      );
                    })()}
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
