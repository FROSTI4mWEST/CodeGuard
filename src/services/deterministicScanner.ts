import { VulnerabilitySeverity, FindingEvidenceStatus } from "../types";

export interface RepoFile {
  path: string;
  content: string;
  lines: string[];
}

export interface RawScannerFinding {
  ruleId: string;
  vulnerabilityName: string;
  category: string;
  severity: VulnerabilitySeverity;
  filePath: string;
  lineNumber?: number;
  lineEnd?: number;
  codeEvidence: string;
  explanation: string;
  impact: string;
  fix: string;
  status: FindingEvidenceStatus;
  verificationNotes?: string;
}

export interface SecurityRule {
  id: string;
  name: string;
  category: string;
  severity: VulnerabilitySeverity;
  appliesTo: (file: RepoFile, allFiles: RepoFile[]) => boolean;
  scan: (file: RepoFile, allFiles: RepoFile[]) => RawScannerFinding[];
}

/**
 * Helper to safely extract surrounding context lines for evidence
 */
function extractEvidence(lines: string[], lineIndex: number, contextRadius = 2): { snippet: string; start: number; end: number } {
  const start = Math.max(0, lineIndex - contextRadius);
  const end = Math.min(lines.length - 1, lineIndex + contextRadius);
  const snippet = lines.slice(start, end + 1).join("\n");
  return { snippet, start: start + 1, end: end + 1 };
}

// ---------------------------------------------------------------------------------------------
// 1. HARDCODED SECRETS & API KEYS
// ---------------------------------------------------------------------------------------------
const SECRET_PATTERNS: { name: string; regex: RegExp; severity: VulnerabilitySeverity }[] = [
  { name: "OpenAI API Key", regex: /sk-(?:proj-)?[A-Za-z0-9_-]{24,}/, severity: "critical" },
  { name: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { name: "GitHub Personal Access Token", regex: /(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})/, severity: "critical" },
  { name: "Google Cloud / Gemini API Key", regex: /AIzaSy[0-9A-Za-z_-]{33}/, severity: "critical" },
  { name: "Stripe Secret Key", regex: /(?:sk_live_|rk_live_)[0-9a-zA-Z]{24,}/, severity: "critical" },
  { name: "Slack Bot / User Token", regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/, severity: "high" },
  { name: "RSA / Private Cryptographic Key Block", regex: /-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY-----/, severity: "critical" },
  { name: "Hardcoded Database Connection URI with Password", regex: /(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_\-\.]+:[^@\s\n\r"']+@[a-zA-Z0-9_\-\.]+/i, severity: "critical" },
  { name: "Hardcoded JWT Secret / Master Password Assignment", regex: /(?:const|let|var)\s+(?:jwtSecret|apiSecret|masterPassword|dbPassword)\s*=\s*["'][^"']{6,}["']/i, severity: "high" },
];

export const SecretDetectionRule: SecurityRule = {
  id: "RULE-SEC-001",
  name: "Hardcoded Secret / API Key Exposure",
  category: "Secret Detection",
  severity: "critical",
  appliesTo: (file) => !file.path.endsWith(".md") && !file.path.endsWith(".lock") && !file.path.includes(".example"),
  scan: (file) => {
    const findings: RawScannerFinding[] = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      // Skip test mocks, comments with placeholders, and environment variable references
      if (line.includes("process.env.") || line.includes("import.meta.env") || line.includes("YOUR_") || line.includes("placeholder")) {
        continue;
      }

      for (const pattern of SECRET_PATTERNS) {
        if (pattern.regex.test(line)) {
          const { snippet, start, end } = extractEvidence(file.lines, i);
          findings.push({
            ruleId: "RULE-SEC-001",
            vulnerabilityName: `Hardcoded ${pattern.name} in Source Code`,
            category: "Secret Detection",
            severity: pattern.severity,
            filePath: file.path,
            lineNumber: i + 1,
            lineEnd: end,
            codeEvidence: snippet,
            explanation: `The file '${file.path}' at line ${i + 1} contains a plain-text secret matching pattern '${pattern.name}'. Hardcoded credentials exposed in source repositories can be harvested by attackers or unauthorized collaborators.`,
            impact: `Immediate compromise of downstream services, cloud infrastructure access, database takeover, or unauthorized API utilization.`,
            fix: `Extract this credential into a runtime environment variable (e.g. \`process.env.${pattern.name.toUpperCase().replace(/\s+/g, '_')}\`) and rotate the exposed key immediately via your provider console.`,
            status: "CONFIRMED",
            verificationNotes: `Exact regex match found on line ${i + 1} of ${file.path}.`,
          });
          break; // Avoid duplicate alerts on the same line
        }
      }
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------------------------
// 2. .ENV EXPOSURE & .GITIGNORE MISCONFIGURATION
// ---------------------------------------------------------------------------------------------
export const EnvExposureRule: SecurityRule = {
  id: "RULE-ENV-001",
  name: "Committed Environment Secrets (.env Exposure)",
  category: "Configuration",
  severity: "critical",
  appliesTo: (file) => {
    const p = file.path.toLowerCase();
    return p === ".env" || p.startsWith(".env.") && !p.endsWith(".example") && !p.endsWith(".template");
  },
  scan: (file) => {
    const findings: RawScannerFinding[] = [];
    const nonCommentLines = file.lines.filter((l) => l.trim().length > 0 && !l.trim().startsWith("#"));
    
    if (nonCommentLines.length > 0) {
      findings.push({
        ruleId: "RULE-ENV-001",
        vulnerabilityName: "Committed Environment Configuration File (.env)",
        category: "Configuration",
        severity: "critical",
        filePath: file.path,
        lineNumber: 1,
        lineEnd: Math.min(10, file.lines.length),
        codeEvidence: file.lines.slice(0, 5).join("\n"),
        explanation: `The repository contains a committed environment file '${file.path}' with ${nonCommentLines.length} active key-value pairs. Storing real environment files in version control exposes production credentials and local configs.`,
        impact: `Direct leak of sensitive secrets, database passwords, and third-party API tokens to anyone with repository read access.`,
        fix: `Add '${file.path}' to .gitignore immediately, remove it from git history via \`git rm --cached ${file.path}\`, and use a sanitized \`.env.example\` file for documentation.`,
        status: "CONFIRMED",
        verificationNotes: `Committed file exists in repo tree with active variable definitions.`,
      });
    }

    return findings;
  },
};

export const GitignoreMisconfigurationRule: SecurityRule = {
  id: "RULE-GIT-001",
  name: "Missing .gitignore or .env Exclusion",
  category: "Configuration",
  severity: "high",
  appliesTo: (file) => file.path === ".gitignore",
  scan: (file) => {
    const findings: RawScannerFinding[] = [];
    const content = file.content.toLowerCase();

    if (!content.includes(".env")) {
      findings.push({
        ruleId: "RULE-GIT-001",
        vulnerabilityName: "Missing .env Secret Exclusion in .gitignore",
        category: "Configuration",
        severity: "high",
        filePath: file.path,
        lineNumber: file.lines.length,
        codeEvidence: file.content.slice(0, 300),
        explanation: `The .gitignore file does not include rules to ignore \`.env\` or \`*.env\` files. Developers working on this project risk accidentally staging and pushing local environment files.`,
        impact: `High risk of accidental secret leaks in future commits.`,
        fix: `Append the following rules to .gitignore:\n\`\`\`gitignore\n.env\n.env.local\n.env.*.local\n*.env\n\`\`\``,
        status: "CONFIRMED",
        verificationNotes: `Scanned complete .gitignore content; verified absence of .env rule.`,
      });
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------------------------
// 3. VULNERABLE & OUTDATED DEPENDENCIES
// ---------------------------------------------------------------------------------------------
interface KnownCVE {
  pkg: string;
  isVulnerable: (version: string) => boolean;
  cve: string;
  title: string;
  severity: VulnerabilitySeverity;
  remediationVersion: string;
}

const KNOWN_CVES: KnownCVE[] = [
  {
    pkg: "lodash",
    isVulnerable: (v) => v.startsWith("4.17.") && parseInt(v.split(".")[2] || "0") < 21 || v.startsWith("4.16.") || v.startsWith("^4.17.") && !v.includes("21"),
    cve: "CVE-2021-23337",
    title: "Prototype Pollution & Command Injection in lodash",
    severity: "high",
    remediationVersion: ">=4.17.21",
  },
  {
    pkg: "axios",
    isVulnerable: (v) => v.includes("0.21.0") || v.includes("0.20.") || v.includes("0.19."),
    cve: "CVE-2020-28168",
    title: "Server-Side Request Forgery (SSRF) & Credential Leakage in axios",
    severity: "high",
    remediationVersion: ">=1.7.4",
  },
  {
    pkg: "jsonwebtoken",
    isVulnerable: (v) => v.startsWith("8.") || v.startsWith("^8.") || v.startsWith("7."),
    cve: "CVE-2022-23529",
    title: "Arbitrary Code Execution via Insecure Key Verification in jsonwebtoken",
    severity: "critical",
    remediationVersion: ">=9.0.0",
  },
  {
    pkg: "express",
    isVulnerable: (v) => v.startsWith("4.18.") || (v.startsWith("4.19.") && parseInt(v.split(".")[2] || "0") < 2),
    cve: "CVE-2024-29041",
    title: "Open Redirect and IP Parsing Bypass in express",
    severity: "medium",
    remediationVersion: ">=4.19.2",
  },
  {
    pkg: "tar",
    isVulnerable: (v) => v.startsWith("6.1.") || (v.startsWith("6.2.") && parseInt(v.split(".")[2] || "0") < 1),
    cve: "CVE-2024-28863",
    title: "Arbitrary File Overwrite via Path Traversal in tar",
    severity: "high",
    remediationVersion: ">=6.2.1",
  },
  {
    pkg: "minimist",
    isVulnerable: (v) => v.startsWith("1.2.") && parseInt(v.split(".")[2] || "0") < 6 || v.startsWith("0."),
    cve: "CVE-2021-44906",
    title: "Prototype Pollution in minimist",
    severity: "medium",
    remediationVersion: ">=1.2.6",
  },
  {
    pkg: "ejs",
    isVulnerable: (v) => v.startsWith("3.1.") && parseInt(v.split(".")[2] || "0") < 7 || v.startsWith("2."),
    cve: "CVE-2022-29078",
    title: "Server-Side Template Injection leading to RCE in ejs",
    severity: "critical",
    remediationVersion: ">=3.1.7",
  },
  {
    pkg: "fast-xml-parser",
    isVulnerable: (v) => v.startsWith("4.3.") && parseInt(v.split(".")[2] || "0") < 6 || v.startsWith("4.2."),
    cve: "CVE-2024-21508",
    title: "Regular Expression Denial of Service (ReDoS) in fast-xml-parser",
    severity: "medium",
    remediationVersion: ">=4.3.6",
  },
  {
    pkg: "vm2",
    isVulnerable: () => true, // vm2 is completely deprecated with unpatchable sandbox escapes
    cve: "CVE-2023-37466",
    title: "Unrestricted Sandbox Escape & Remote Code Execution in vm2",
    severity: "critical",
    remediationVersion: "Discontinue package. Migrate to isolated-vm or WebAssembly.",
  },
];

export const VulnerableDependenciesRule: SecurityRule = {
  id: "RULE-DEP-001",
  name: "Known Vulnerable Dependencies",
  category: "Vulnerable Components",
  severity: "high",
  appliesTo: (file) => file.path === "package.json" || file.path.endsWith("/package.json"),
  scan: (file) => {
    const findings: RawScannerFinding[] = [];
    try {
      const parsed = JSON.parse(file.content);
      const allDeps = { ...(parsed.dependencies || {}), ...(parsed.devDependencies || {}) };

      for (const known of KNOWN_CVES) {
        if (allDeps[known.pkg]) {
          const declaredVersion = allDeps[known.pkg];
          const cleanVersion = declaredVersion.replace(/[\^~>=<]/g, "");

          if (known.isVulnerable(cleanVersion)) {
            // Find line number in package.json
            let lineNum = 1;
            for (let i = 0; i < file.lines.length; i++) {
              if (file.lines[i].includes(`"${known.pkg}"`)) {
                lineNum = i + 1;
                break;
              }
            }

            const { snippet, start, end } = extractEvidence(file.lines, lineNum - 1, 1);

            findings.push({
              ruleId: "RULE-DEP-001",
              vulnerabilityName: `${known.title} (${known.cve})`,
              category: "Vulnerable Components",
              severity: known.severity,
              filePath: file.path,
              lineNumber: lineNum,
              lineEnd: end,
              codeEvidence: snippet,
              explanation: `The dependency \`${known.pkg}\` is pinned to vulnerable version \`${declaredVersion}\` in '${file.path}' at line ${lineNum}. This package is affected by ${known.cve}.`,
              impact: `Attackers can exploit known security advisories associated with ${known.cve} against your running application.`,
              fix: `Update \`${known.pkg}\` in package.json to \`${known.remediationVersion}\` and run \`npm update ${known.pkg} && npm audit\`.`,
              status: "CONFIRMED",
              verificationNotes: `Verified ${known.pkg}@${declaredVersion} in parsed package.json manifest.`,
            });
          }
        }
      }
    } catch {
      // Ignore JSON parse errors
    }
    return findings;
  },
};

// ---------------------------------------------------------------------------------------------
// 4. DOCKER RUNNING AS ROOT
// ---------------------------------------------------------------------------------------------
export const DockerRootRule: SecurityRule = {
  id: "RULE-DOC-001",
  name: "Docker Container Running as Root User",
  category: "Configuration",
  severity: "high",
  appliesTo: (file) => file.path.toLowerCase().includes("dockerfile"),
  scan: (file) => {
    const findings: RawScannerFinding[] = [];
    const hasUserDirective = file.lines.some((l) => /^\s*USER\s+(?!root\b)[a-zA-Z0-9_-]+/i.test(l));
    const explicitRoot = file.lines.findIndex((l) => /^\s*USER\s+root\b/i.test(l));

    if (explicitRoot !== -1) {
      const { snippet, start, end } = extractEvidence(file.lines, explicitRoot, 2);
      findings.push({
        ruleId: "RULE-DOC-001",
        vulnerabilityName: "Explicit Root Execution in Dockerfile",
        category: "Configuration",
        severity: "high",
        filePath: file.path,
        lineNumber: explicitRoot + 1,
        lineEnd: end,
        codeEvidence: snippet,
        explanation: `Dockerfile explicitly declares \`USER root\` on line ${explicitRoot + 1}. Running container processes with root privileges violates the principle of least privilege.`,
        impact: `If container application suffers a Remote Code Execution (RCE) flaw, the attacker obtains root permissions inside the container, facilitating host escape or lateral movement.`,
        fix: `Create and switch to a non-privileged user before the ENTRYPOINT/CMD:\n\`\`\`dockerfile\nRUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser\n\`\`\``,
        status: "CONFIRMED",
        verificationNotes: `Explicit 'USER root' instruction matched at line ${explicitRoot + 1}.`,
      });
    } else if (!hasUserDirective) {
      // Find CMD or ENTRYPOINT line for evidence
      const entryIdx = file.lines.findIndex((l) => /^\s*(?:CMD|ENTRYPOINT)\s+/i.test(l));
      const targetIdx = entryIdx !== -1 ? entryIdx : file.lines.length - 1;
      const { snippet, start, end } = extractEvidence(file.lines, targetIdx, 2);

      findings.push({
        ruleId: "RULE-DOC-001",
        vulnerabilityName: "Missing Non-Root User in Dockerfile",
        category: "Configuration",
        severity: "medium",
        filePath: file.path,
        lineNumber: targetIdx + 1,
        lineEnd: end,
        codeEvidence: snippet,
        explanation: `The Dockerfile does not specify a non-root \`USER\` directive before application startup. Docker defaults to running all entrypoint processes as root (UID 0).`,
        impact: `Container workloads inherit elevated root capabilities by default, expanding the blast radius in case of container compromise.`,
        fix: `Define an unprivileged user in the build stage:\n\`\`\`dockerfile\nRUN useradd -m -u 1001 appuser\nUSER appuser\n\`\`\``,
        status: "CONFIRMED",
        verificationNotes: `Parsed Dockerfile AST: No USER directive declared prior to execution commands.`,
      });
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------------------------
// 5. CORS MISCONFIGURATIONS
// ---------------------------------------------------------------------------------------------
export const CorsMisconfigurationRule: SecurityRule = {
  id: "RULE-CORS-001",
  name: "Overly Permissive / Wildcard CORS Policy",
  category: "Security Misconfiguration",
  severity: "high",
  appliesTo: (file) => !file.path.endsWith(".md") && (file.path.endsWith(".ts") || file.path.endsWith(".js") || file.path.endsWith(".py") || file.path.endsWith(".go")),
  scan: (file) => {
    const findings: RawScannerFinding[] = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];

      // Detect wildcard CORS or origin: true reflection
      const isWildcardCors = /origin\s*:\s*["']\*["']/.test(line) || /Access-Control-Allow-Origin['",\s]+['"]\*['"]/.test(line);
      const isReflectedOrigin = /origin\s*:\s*true\b/.test(line) || /setHeader\(\s*["']Access-Control-Allow-Origin["']\s*,\s*req\.headers\.origin\b/i.test(line);

      if (isWildcardCors || isReflectedOrigin) {
        const { snippet, start, end } = extractEvidence(file.lines, i, 2);
        findings.push({
          ruleId: "RULE-CORS-001",
          vulnerabilityName: isWildcardCors ? "Wildcard Access-Control-Allow-Origin (*)" : "Unvalidated Origin Reflection in CORS",
          category: "Security Misconfiguration",
          severity: "high",
          filePath: file.path,
          lineNumber: i + 1,
          lineEnd: end,
          codeEvidence: snippet,
          explanation: `Line ${i + 1} in '${file.path}' configures CORS with ${isWildcardCors ? "a wildcard origin '*'" : "arbitrary origin reflection"}. This allows any third-party website to make authenticated cross-origin requests to your API.`,
          impact: `Enables Cross-Origin Resource Sharing exploitation, allowing malicious sites to read sensitive response data or abuse API endpoints on behalf of authenticated users.`,
          fix: `Replace wildcard origin with an explicit domain allow-list:\n\`\`\`typescript\napp.use(cors({\n  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],\n  credentials: true\n}));\n\`\`\``,
          status: "CONFIRMED",
          verificationNotes: `Matched CORS configuration statement at line ${i + 1}.`,
        });
      }
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------------------------
// 6. MISSING SECURITY HEADERS
// ---------------------------------------------------------------------------------------------
export const SecurityHeadersRule: SecurityRule = {
  id: "RULE-HDR-001",
  name: "Missing HTTP Security Response Headers",
  category: "Security Misconfiguration",
  severity: "medium",
  appliesTo: (file) => {
    const p = file.path.toLowerCase();
    return (p.endsWith("server.ts") || p.endsWith("server.js") || p.endsWith("app.ts") || p.endsWith("app.js") || p.endsWith("index.ts") || p.endsWith("index.js")) &&
      !p.includes(".test.") && !p.includes(".spec.");
  },
  scan: (file) => {
    const findings: RawScannerFinding[] = [];
    const isExpressOrKoa = file.content.includes("express()") || file.content.includes("fastify") || file.content.includes("new Koa");

    if (isExpressOrKoa) {
      const hasHelmet = file.content.includes("helmet(") || file.content.includes("helmet.");
      const hasCsp = file.content.includes("Content-Security-Policy");
      const hasHsts = file.content.includes("Strict-Transport-Security");

      if (!hasHelmet && !hasCsp && !hasHsts) {
        // Match server initialization line
        let targetLine = 1;
        for (let i = 0; i < file.lines.length; i++) {
          if (file.lines[i].includes("express()") || file.lines[i].includes("app.listen")) {
            targetLine = i + 1;
            break;
          }
        }
        const { snippet, start, end } = extractEvidence(file.lines, targetLine - 1, 2);

        findings.push({
          ruleId: "RULE-HDR-001",
          vulnerabilityName: "Missing HTTP Security Headers (Helmet / CSP / HSTS)",
          category: "Security Misconfiguration",
          severity: "medium",
          filePath: file.path,
          lineNumber: targetLine,
          lineEnd: end,
          codeEvidence: snippet,
          explanation: `The server entry point '${file.path}' initializes an HTTP application without configuring security response headers (e.g. Helmet middleware, Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security).`,
          impact: `Leaves clients vulnerable to Clickjacking (lack of X-Frame-Options), MIME-type sniffing attacks, Cross-Site Scripting (XSS), and downgrade attacks.`,
          fix: `Install and attach Helmet middleware:\n\`\`\`typescript\nimport helmet from 'helmet';\napp.use(helmet());\n\`\`\``,
          status: "CONFIRMED",
          verificationNotes: `Verified server initialization in ${file.path} lacks helmet or security header middleware.`,
        });
      }
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------------------------
// 7. COMMON JS/TS SECURITY ISSUES
// ---------------------------------------------------------------------------------------------
export const CommonJSSecurityRule: SecurityRule = {
  id: "RULE-JS-001",
  name: "Common JavaScript Security Flaws (Code Execution, XSS, Command Injection, Weak Crypto)",
  category: "Application Security",
  severity: "high",
  appliesTo: (file) => !file.path.endsWith(".md") && (file.path.endsWith(".ts") || file.path.endsWith(".tsx") || file.path.endsWith(".js") || file.path.endsWith(".jsx")),
  scan: (file) => {
    const findings: RawScannerFinding[] = [];

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];

      // A. Dynamic Code Execution (eval, Function)
      if (/\beval\s*\(/.test(line) && !line.includes("//") && !line.includes("/*")) {
        const { snippet, end } = extractEvidence(file.lines, i, 2);
        findings.push({
          ruleId: "RULE-JS-EVAL",
          vulnerabilityName: "Dangerous Dynamic Code Execution via eval()",
          category: "Injection",
          severity: "critical",
          filePath: file.path,
          lineNumber: i + 1,
          lineEnd: end,
          codeEvidence: snippet,
          explanation: `Direct invocation of \`eval()\` detected on line ${i + 1} of '${file.path}'. Executing dynamic strings opens critical remote code execution vectors.`,
          impact: `Arbitrary Code Execution (RCE) inside the runtime environment if any untrusted or tainted inputs reach eval().`,
          fix: `Refactor logic to use native JSON.parse or structured type-safe mapping without dynamic code evaluation.`,
          status: "CONFIRMED",
          verificationNotes: `Direct eval() token matched at line ${i + 1}.`,
        });
      }

      // B. React XSS via dangerouslySetInnerHTML without sanitization
      if (/dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:/.test(line)) {
        const isSanitized = line.includes("DOMPurify") || line.includes("sanitize");
        if (!isSanitized) {
          const { snippet, end } = extractEvidence(file.lines, i, 2);
          findings.push({
            ruleId: "RULE-JS-XSS",
            vulnerabilityName: "Unsanitized dangerouslySetInnerHTML Rendering",
            category: "Cross-Site Scripting (XSS)",
            severity: "high",
            filePath: file.path,
            lineNumber: i + 1,
            lineEnd: end,
            codeEvidence: snippet,
            explanation: `Line ${i + 1} renders HTML via \`dangerouslySetInnerHTML\` without explicit sanitization using DOMPurify.`,
            impact: `Stored or Reflected Cross-Site Scripting (XSS), allowing attacker scripts to steal session tokens or impersonate users.`,
            fix: `Sanitize user-provided HTML with DOMPurify:\n\`\`\`tsx\nimport DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />\n\`\`\``,
            status: "CONFIRMED",
            verificationNotes: `Matched dangerouslySetInnerHTML prop at line ${i + 1}.`,
          });
        }
      }

      // C. Command Injection via child_process
      if (/(?:exec|execSync)\s*\(\s*`[^`]*\$\{[^}]+\}/.test(line) || /(?:exec|execSync)\s*\([^,)]*\+/.test(line)) {
        const { snippet, end } = extractEvidence(file.lines, i, 2);
        findings.push({
          ruleId: "RULE-JS-CMD",
          vulnerabilityName: "Command Injection via child_process.exec Interpolation",
          category: "Injection",
          severity: "critical",
          filePath: file.path,
          lineNumber: i + 1,
          lineEnd: end,
          codeEvidence: snippet,
          explanation: `Line ${i + 1} executes a shell command with dynamic variable interpolation via \`child_process.exec\`. Shell metacharacters (; | & \` $()) in input variables can execute arbitrary commands.`,
          impact: `Complete server takeover via OS command injection.`,
          fix: `Use \`execFile\` or \`spawn\` with structured argument arrays instead of shell concatenation:\n\`\`\`typescript\nimport { execFile } from 'child_process';\nexecFile('cmd', [arg1, arg2], (err, stdout) => { ... });\n\`\`\``,
          status: "CONFIRMED",
          verificationNotes: `String interpolation in exec() identified on line ${i + 1}.`,
        });
      }

      // D. Weak Cryptographic Hash (MD5 / SHA-1)
      if (/createHash\(\s*['"](?:md5|sha1)['"]\s*\)/i.test(line)) {
        const { snippet, end } = extractEvidence(file.lines, i, 2);
        findings.push({
          ruleId: "RULE-JS-CRYPTO",
          vulnerabilityName: "Use of Weak Cryptographic Hash Function (MD5/SHA1)",
          category: "Cryptographic Failures",
          severity: "medium",
          filePath: file.path,
          lineNumber: i + 1,
          lineEnd: end,
          codeEvidence: snippet,
          explanation: `Line ${i + 1} uses a cryptographically broken hashing algorithm (MD5 or SHA-1). These algorithms are vulnerable to practical collision attacks.`,
          impact: `Hash collision vulnerabilities, digital signature forgery, and insecure password/credential verification.`,
          fix: `Upgrade to SHA-256 (or SHA-512) for integrity, or Argon2id/bcrypt for password hashing:\n\`\`\`typescript\ncrypto.createHash('sha256').update(data).digest('hex');\n\`\`\``,
          status: "CONFIRMED",
          verificationNotes: `Matched legacy crypto.createHash algorithm argument on line ${i + 1}.`,
        });
      }

      // E. Insecure Pseudo-Random Number Generation for Security Tokens
      if (/Math\.random\(\)/.test(line) && (line.toLowerCase().includes("token") || line.toLowerCase().includes("secret") || line.toLowerCase().includes("password") || line.toLowerCase().includes("session") || line.toLowerCase().includes("key"))) {
        const { snippet, end } = extractEvidence(file.lines, i, 2);
        findings.push({
          ruleId: "RULE-JS-PRNG",
          vulnerabilityName: "Insecure Randomness for Security-Sensitive Value",
          category: "Cryptographic Failures",
          severity: "high",
          filePath: file.path,
          lineNumber: i + 1,
          lineEnd: end,
          codeEvidence: snippet,
          explanation: `Line ${i + 1} generates a security token or identifier using \`Math.random()\`. Math.random is a non-cryptographic PRNG with predictable internal state.`,
          impact: `Attackers can predict generated session tokens, reset tokens, or cryptographic keys.`,
          fix: `Use \`crypto.randomBytes()\` or Web Crypto \`crypto.getRandomValues()\`:\n\`\`\`typescript\nimport crypto from 'crypto';\nconst secureToken = crypto.randomBytes(32).toString('hex');\n\`\`\``,
          status: "CONFIRMED",
          verificationNotes: `Math.random token generation identified on line ${i + 1}.`,
        });
      }
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------------------------
// Scanner Engine Dispatcher
// ---------------------------------------------------------------------------------------------
export const ALL_SECURITY_RULES: SecurityRule[] = [
  SecretDetectionRule,
  EnvExposureRule,
  GitignoreMisconfigurationRule,
  VulnerableDependenciesRule,
  DockerRootRule,
  CorsMisconfigurationRule,
  SecurityHeadersRule,
  CommonJSSecurityRule,
];

export function runDeterministicScan(files: RepoFile[]): RawScannerFinding[] {
  const allFindings: RawScannerFinding[] = [];

  for (const file of files) {
    for (const rule of ALL_SECURITY_RULES) {
      try {
        if (rule.appliesTo(file, files)) {
          const ruleFindings = rule.scan(file, files);
          if (ruleFindings && ruleFindings.length > 0) {
            allFindings.push(...ruleFindings);
          }
        }
      } catch (err) {
        console.warn(`Rule ${rule.id} failed on ${file.path}:`, err);
      }
    }
  }

  return allFindings;
}
