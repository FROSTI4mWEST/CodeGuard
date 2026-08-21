export type UserRole = 'admin' | 'developer' | 'viewer';

export interface UserProfile {
  uid: string;
  email: string;
  displayName?: string;
  photoURL?: string;
  role: UserRole;
  createdAt: string;
  updatedAt?: string;
}

export type ScanStatus = 'pending' | 'scanning' | 'completed' | 'failed';

export interface Repository {
  id: string;
  name: string;
  owner: string;
  full_name: string;
  url: string;
  visibility: 'public' | 'private';
  healthScore?: number;
  lastScanId?: string;
  lastScanDate?: string;
  createdAt: string;
  addedBy: string;
}

export interface Scan {
  id: string;
  repositoryId: string;
  status: ScanStatus;
  score?: number;
  findingsCount?: number;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  scanDuration?: number;
  createdAt: string;
}

export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low';
export type VulnerabilityStatus = 'open' | 'in-progress' | 'resolved' | 'ignored';

export type FindingEvidenceStatus = 'CONFIRMED' | 'UNCONFIRMED';

export interface Vulnerability {
  id: string;
  scanId: string;
  repositoryId: string;
  category: string;
  title: string;
  description: string;
  risk: string;
  severity: VulnerabilitySeverity;
  remediation: string;
  codeSnippet?: string;
  codeEvidence?: string;
  filePath: string;
  lineNumber?: number;
  lineStart?: number;
  lineEnd?: number;
  evidenceStatus: FindingEvidenceStatus;
  explanation?: string;
  impact?: string;
  fix?: string;
  ruleId?: string;
  verified?: boolean;
  status: VulnerabilityStatus;
  detectedAt: string;
  resolvedAt?: string;
  resolvedBy?: string;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  description: string;
  rules: string[];
  createdAt: string;
  createdBy: string;
}

export interface AuditLog {
  id: string;
  userId: string;
  userEmail: string;
  action: string;
  timestamp: string;
  details: string;
  resourceType?: string;
  resourceId?: string;
}
