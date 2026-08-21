import { Repository, Scan, Vulnerability } from '../types';

export function generateJSONReport(repo: Repository, scans: Scan[], vulnerabilities: Vulnerability[]) {
  const reportData = {
    reportTitle: `Security Audit Report - ${repo.full_name}`,
    generatedAt: new Date().toISOString(),
    repository: {
      name: repo.name,
      owner: repo.owner,
      fullName: repo.full_name,
      url: repo.url,
      visibility: repo.visibility,
      healthScore: repo.healthScore ?? 100,
      lastScanDate: repo.lastScanDate || null
    },
    summary: {
      totalScans: scans.length,
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: vulnerabilities.filter(v => v.severity === 'critical').length,
      highCount: vulnerabilities.filter(v => v.severity === 'high').length,
      mediumCount: vulnerabilities.filter(v => v.severity === 'medium').length,
      lowCount: vulnerabilities.filter(v => v.severity === 'low').length,
      openCount: vulnerabilities.filter(v => v.status === 'open').length,
      resolvedCount: vulnerabilities.filter(v => v.status === 'resolved').length
    },
    scans: scans.map(s => ({
      scanId: s.id,
      status: s.status,
      score: s.score,
      findingsCount: s.findingsCount,
      createdAt: s.createdAt
    })),
    vulnerabilities: vulnerabilities.map(v => ({
      id: v.id,
      title: v.title,
      severity: v.severity,
      category: v.category,
      filePath: v.filePath,
      lineNumber: v.lineNumber || v.lineStart || null,
      evidenceStatus: v.evidenceStatus || (v.verified ? 'CONFIRMED' : 'UNCONFIRMED'),
      codeEvidence: v.codeEvidence || v.codeSnippet || null,
      status: v.status,
      explanation: v.explanation || v.description,
      impact: v.impact || v.risk,
      fix: v.fix || v.remediation,
      ruleId: v.ruleId || null,
      detectedAt: v.detectedAt
    }))
  };

  const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `CodeGuard_Audit_${repo.name}_${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function generateMarkdownReport(repo: Repository, scans: Scan[], vulnerabilities: Vulnerability[]) {
  const criticals = vulnerabilities.filter(v => v.severity === 'critical');
  const highs = vulnerabilities.filter(v => v.severity === 'high');
  const mediums = vulnerabilities.filter(v => v.severity === 'medium');
  const lows = vulnerabilities.filter(v => v.severity === 'low');

  const md = `# CodeGuard Security Audit Report

**Repository:** \`${repo.full_name}\`  
**Security Score:** \`${repo.healthScore ?? 100}%\`  
**Generated On:** ${new Date().toLocaleString()}  
**Repository URL:** [${repo.url}](${repo.url})  

---

## Executive Summary

| Metric | Count |
| :--- | :--- |
| **Total Scans Conducted** | ${scans.length} |
| **Total Vulnerabilities Detected** | ${vulnerabilities.length} |
| **Critical Risk** | ${criticals.length} |
| **High Risk** | ${highs.length} |
| **Medium Risk** | ${mediums.length} |
| **Low Risk** | ${lows.length} |
| **Open Vulnerabilities** | ${vulnerabilities.filter(v => v.status === 'open').length} |
| **Resolved Findings** | ${vulnerabilities.filter(v => v.status === 'resolved').length} |

---

## Detailed Vulnerability Breakdown

${vulnerabilities.length === 0 ? '_No vulnerabilities detected in this repository._' : vulnerabilities.map((v, idx) => `
### ${idx + 1}. [${v.severity.toUpperCase()}] ${v.title}

- **Evidence Status:** \`${v.evidenceStatus || (v.verified ? 'CONFIRMED' : 'UNCONFIRMED')}\`
- **Category:** \`${v.category}\`
- **File Location:** \`${v.filePath}\`${(v.lineNumber || v.lineStart) ? ` (Line ${v.lineNumber || v.lineStart})` : ''}
- **Lifecycle Status:** \`${v.status.toUpperCase()}\`
- **Rule ID:** \`${v.ruleId || 'SAST-AUTO'}\`
- **Detected Date:** ${new Date(v.detectedAt).toLocaleString()}

#### Explanation
${v.explanation || v.description}

#### Impact & Attack Scenario
${v.impact || v.risk}

#### Verified Fix Patch
${v.fix || v.remediation}

${(v.codeEvidence || v.codeSnippet) ? `#### Verbatim Code Evidence
\`\`\`
${v.codeEvidence || v.codeSnippet}
\`\`\`` : ''}

---
`).join('\n')}

_Generated automatically by CodeGuard SAST Automated Security Intelligence._
`;

  const blob = new Blob([md], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `CodeGuard_Audit_${repo.name}_${new Date().toISOString().slice(0, 10)}.md`;
  a.click();
  URL.revokeObjectURL(url);
}

export function openPrintableReport(repo: Repository, scans: Scan[], vulnerabilities: Vulnerability[]) {
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <title>CodeGuard Audit Report - ${repo.full_name}</title>
        <style>
          body { font-family: monospace, sans-serif; background: #020813; color: #00b4d8; padding: 40px; margin: 0; }
          h1, h2, h3 { text-transform: uppercase; letter-spacing: 1px; color: #00b4d8; }
          .header { border-bottom: 2px solid #00b4d8; padding-bottom: 20px; margin-bottom: 30px; }
          .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
          .card { border: 1px solid #00b4d8; background: #041022; padding: 15px; text-align: center; }
          .card-value { font-size: 24px; font-weight: bold; }
          .card-label { font-size: 10px; opacity: 0.8; margin-top: 5px; color: #0077b6; }
          table { width: 100%; border-collapse: collapse; margin-top: 20px; }
          th, td { border: 1px solid #00b4d8; padding: 10px; text-align: left; font-size: 12px; }
          th { background: #041022; }
          .badge { padding: 2px 6px; font-weight: bold; font-size: 10px; display: inline-block; }
          .critical { background: #ff3344; color: #000; }
          .high { background: #ffcc00; color: #000; }
          .medium { background: #00b4d8; color: #000; }
          .low { background: #0077b6; color: #fff; }
          @media print {
            body { background: #fff; color: #000; }
            .header, .card, table, th, td { border-color: #000; color: #000; background: #fff; }
            h1, h2, h3 { color: #000; }
          }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>CODEGUARD SECURITY AUDIT REPORT</h1>
          <p><strong>REPOSITORY:</strong> ${repo.full_name} (${repo.visibility.toUpperCase()})</p>
          <p><strong>SECURITY SCORE:</strong> ${repo.healthScore ?? 100}% | <strong>AUDIT DATE:</strong> ${new Date().toLocaleString()}</p>
        </div>

        <div class="grid">
          <div class="card"><div class="card-value">${vulnerabilities.length}</div><div class="card-label">TOTAL FINDINGS</div></div>
          <div class="card"><div class="card-value">${vulnerabilities.filter(v => v.severity === 'critical').length}</div><div class="card-label">CRITICAL RISKS</div></div>
          <div class="card"><div class="card-value">${vulnerabilities.filter(v => v.severity === 'high').length}</div><div class="card-label">HIGH RISKS</div></div>
          <div class="card"><div class="card-value">${vulnerabilities.filter(v => v.status === 'resolved').length}</div><div class="card-label">RESOLVED</div></div>
        </div>

        <h2>VULNERABILITY FINDINGS LIST</h2>
        <table>
          <thead>
            <tr>
              <th>SEVERITY</th>
              <th>TITLE</th>
              <th>CATEGORY</th>
              <th>FILE PATH</th>
              <th>STATUS</th>
            </tr>
          </thead>
          <tbody>
            ${vulnerabilities.map(v => `
              <tr>
                <td><span class="badge ${v.severity}">${v.severity.toUpperCase()}</span></td>
                <td><strong>${v.title}</strong></td>
                <td>${v.category}</td>
                <td>${v.filePath}</td>
                <td>${v.status.toUpperCase()}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>

        <script>
          window.onload = function() {
            window.print();
          };
        </script>
      </body>
    </html>
  `;

  const printWindow = window.open('', '_blank');
  if (printWindow) {
    printWindow.document.write(html);
    printWindow.document.close();
  } else {
    // If popups are restricted in iframe, trigger HTML download fallback
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CodeGuard_Audit_${repo.name}_${new Date().toISOString().slice(0, 10)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  }
}
