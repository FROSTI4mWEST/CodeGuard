
export interface SecurityPattern {
  category: string;
  pattern: string;
  verifiedRemediation: string;
  source: string;
}

export const VERIFIED_PATTERNS: SecurityPattern[] = [
  {
    category: "Injection",
    pattern: "SQL, NoSQL, OS Command Injection",
    verifiedRemediation: "Always use parameterized queries (Prepared Statements) for SQL. Use typed ORMs like Prisma or TypeORM. For OS commands, avoid shell execution and use execFile with controlled arguments.",
    source: "OWASP Top 10:2021-A03"
  },
  {
    category: "Broken Access Control",
    pattern: "IDOR, Path Traversal",
    verifiedRemediation: "Implement server-side authorization checks for every resource access. Never trust client-provided IDs without verifying ownership in the database session context.",
    source: "OWASP Top 10:2021-A01"
  },
  {
    category: "Cryptographic Failures",
    pattern: "Hardcoded Secrets, Weak Hashing",
    verifiedRemediation: "Use environment variables for all secrets. For password storage, use Argon2id or bcrypt with a minimum work factor of 10. Implement TLS 1.3 for all data in transit.",
    source: "OWASP Top 10:2021-A02"
  },
  {
    category: "Insecure Design",
    pattern: "Lack of Input Validation",
    verifiedRemediation: "Implement 'Allow-list' validation for all user inputs using schemas (e.g., Zod or Joi). Sanitize output to prevent XSS using libraries like DOMPurify.",
    source: "OWASP Top 10:2021-A04"
  },
  {
    category: "Security Misconfiguration",
    pattern: "Default Credentials, Open Ports",
    verifiedRemediation: "Disable all unnecessary services and features. Ensure security headers (HSTS, CSP, X-Frame-Options) are present. Remove default credentials and sample configurations.",
    source: "OWASP Top 10:2021-A05"
  },
  {
    category: "Vulnerable Components",
    pattern: "Outdated Libraries",
    verifiedRemediation: "Use automated tools like 'npm audit' or Snyk. Pin specific versions of dependencies and keep them updated. Review licensing of third-party software.",
    source: "OWASP Top 10:2021-A06"
  }
];

export function getVerifiedContext(category: string): string {
  const matching = VERIFIED_PATTERNS.find(p => category.toLowerCase().includes(p.category.toLowerCase()));
  if (matching) {
    return `Verified Fix Context from ${matching.source}: ${matching.verifiedRemediation}`;
  }
  return "Use general industry best practices from OWASP and GitHub Security Advisories.";
}
