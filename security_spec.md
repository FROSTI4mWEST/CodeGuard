# Security Specification for CodeGuard

## Data Invariants
- A Scan must always belong to a valid Repository.
- A Vulnerability must always belong to a valid Repository and Scan.
- Only Admins and Developers can trigger scans.
- Viewers can only read data.
- Users can only access repositories they have permission for (for now, simplify to all authenticated users for this MVP, but with role-based checks for writes).
- Critical fields like `severity` and `severityCounts` must be within allowed ranges/values.
- Immutability of sensitive fields like `uid`, `detectedAt`, and `repositoryId`.

## The "Dirty Dozen" Payloads
1. **Identity Spoofing**: Attempt to create a user profile with a different `uid`.
2. **Privilege Escalation**: Attempt to update `role` to 'admin' as a regular user.
3. **Shadow Update**: Add a `ghostField` to a scan result.
4. **ID Poisoning**: Inject a 1MB string as `repositoryId`.
5. **Relationship Breaking**: Create a Scan for a non-existent Repository.
6. **Time Spoofing**: Provide a future `createdAt` timestamp from the client.
7. **Negative Counts**: Setting `criticalCount` to -1.
8. **Invalid Enum**: Setting `severity` to 'super-dangerous'.
9. **State Shortcut**: Moving a scan status from 'failed' directly to 'completed' without 'scanning' state.
10. **Unauthorized Read**: Viewer attempting to delete an `AuditLog`.
11. **PII Leak**: Accessing other users' private profile data (if any).
12. **Policy Bypass**: Updating a closed Vulnerability status back to 'open' without proper authorization.

## Test Runner
The tests will ensure all these malicious actions return `PERMISSION_DENIED`.
