# TrustVault Threat Model & Risk Analysis (THREATS.md)

This threat model outlines potential attack vectors against the **TrustVault** platform, detailing the potential impact, concrete architectural mitigations implemented in source code, associated automated test verification, residual risks, and justifications.

---

## Threat Matrix Overview

| Threat ID | Threat Category | Severity | Implemented Mitigation | Residual Risk Status |
|---|---|---|---|---|
| **THREAT-01** | Insecure Direct Object Reference (IDOR) | CRITICAL | UUID primary keys + DB-level permission queries | Mitigated; accepted UUID entropy limits |
| **THREAT-02** | Broken Access Control | CRITICAL | Centralized authorization service on every endpoint | Mitigated; verified with 40 tests |
| **THREAT-03** | Privilege Escalation | HIGH | Strict RBAC in Django models & view layer | Mitigated |
| **THREAT-04** | Stolen Session Cookies | HIGH | HttpOnly, Secure, 2-hr expiry, regenerate on login | Accepted client-side endpoint risk |
| **THREAT-05** | Unauthorized Direct File Access | CRITICAL | PrivateFileSystemStorage (no public MEDIA_URL) | Fully Mitigated |
| **THREAT-06** | Reuse of Revoked Links | CRITICAL | Dynamic DB authorization check per download request | Fully Mitigated |
| **THREAT-07** | Public Media Directory Exposure | CRITICAL | Files stored outside static/media roots; base_url=None | Fully Mitigated |
| **THREAT-08** | Directory & Path Traversal | HIGH | Filename sanitization, UUID paths, os.path.basename | Fully Mitigated |
| **THREAT-09** | Malicious File Uploads | CRITICAL | Magic bytes signature inspection, executable block | Mitigated |
| **THREAT-10** | MIME Type Spoofing | HIGH | Binary header inspection overrides declared header | Fully Mitigated |
| **THREAT-11** | Double-Extension Attacks | MEDIUM | Regex inspection rejects inner dangerous tokens | Fully Mitigated |
| **THREAT-12** | SQL Injection | HIGH | Django ORM parameterized queries exclusively | Fully Mitigated |
| **THREAT-13** | Cross-Site Scripting (XSS) | HIGH | Django template auto-escaping, CSP headers | Fully Mitigated |
| **THREAT-14** | Cross-Site Request Forgery (CSRF) | HIGH | Mandatory CSRF tokens on all state-modifying requests | Fully Mitigated |
| **THREAT-15** | Brute-Force Login Attacks | MEDIUM | Audit logging on failed logins + security alert heuristic | Accepted external network rate-limit reliance |
| **THREAT-16** | Password Attacks | MEDIUM | PBKDF2-SHA256 password hashing + complexity validators | Fully Mitigated |
| **THREAT-17** | Audit Log Tampering | CRITICAL | Append-only model checks + SHA-256 hash chaining | Mitigated; external backup recommended |
| **THREAT-18** | Permission Race Conditions | HIGH | Atomic transactions + database select_for_update() | Fully Mitigated |
| **THREAT-19** | Information Leakage via Search | HIGH | Backend QuerySet filtering strictly limits discovery | Fully Mitigated |
| **THREAT-20** | Information Leakage via Errors | MEDIUM | Generic error messages (403/404) conceal internals | Fully Mitigated |
| **THREAT-21** | Administrator Privilege Misuse | HIGH | Admins cannot download document content by default | Fully Mitigated |
| **THREAT-22** | Retained Offline Downloaded Copies | MEDIUM | Documented client-side retention limit | Accepted residual risk (inherent to compute) |
| **THREAT-23** | Database Compromise | CRITICAL | Hashes irreversibly salted; files isolated on disk | Accepted threat without full envelope encryption |
| **THREAT-24** | Backup Exposure | HIGH | Recommendations for encrypted backups documented | Operational risk; policy-managed |
| **THREAT-25** | Denial of Service via Large Files | MEDIUM | 25 MB file size limit enforced prior to disk save | Fully Mitigated |
| **THREAT-26** | Unauthorized API Access | HIGH | DRF IsAuthenticated + Session/Basic auth on every route | Fully Mitigated |
| **THREAT-27** | Deactivated Account Session Reuse | HIGH | is_active checked in middleware and authorization service | Fully Mitigated |
| **THREAT-28** | Insecure Document Version Access | HIGH | Version requests route through same authorization logic | Fully Mitigated |

---

## Detailed Threat Breakdown (28 Specific Threats)

### 1. Insecure Direct Object Reference (IDOR)
- **Scenario:** Attacker guesses sequential IDs (e.g. `/documents/1`, `/documents/2`) to access confidential files belonging to other organizations.
- **Impact:** Complete confidentiality breach of sensitive corporate documents.
- **Mitigation:**
  1. Primary keys are cryptographically random UUIDv4 identifiers, rendering enumeration computationally infeasible.
  2. Every endpoint calls `can_view_document(user, document)` or `can_download_document(user, document)`, which verifies database-backed ownership or explicit grant regardless of submitted ID.
- **Verification:** Verified by `MasterTrustVaultSecurityTests.test_15_idor_prevention`.
- **Remaining Risk:** None within application scope.

### 2. Broken Access Control
- **Scenario:** A user navigates directly to an unlinked download URL or modifies form parameters to access unauthorized documents.
- **Impact:** Unauthorized viewing or exfiltration of proprietary documents.
- **Mitigation:** Centralized authorization service (`documents/services.py`). Frontend button visibility is treated merely as UI UX polish; every backend view independently executes database queries to evaluate permissions.
- **Verification:** `MasterTrustVaultSecurityTests.test_03_viewer_cannot_access_unshared_document`, `test_07_unauthorized_users_cannot_download`.
- **Remaining Risk:** None.

### 3. Privilege Escalation
- **Scenario:** A Viewer attempts to promote themselves to Document Owner or Administrator by submitting modified POST bodies.
- **Impact:** Unauthorized administrative access and system compromise.
- **Mitigation:** Role fields are strictly managed server-side. Regular user forms do not expose the `role` field for self-modification; only system administrators can update user roles via `accounts:toggle_user_status`.
- **Verification:** `MasterTrustVaultSecurityTests.test_09_unauthorized_users_cannot_change_permissions`.
- **Remaining Risk:** None.

### 4. Stolen Session Cookies
- **Scenario:** An attacker intercepts or extracts session cookies to impersonate a legitimate user.
- **Impact:** Account takeover and unauthorized vault access.
- **Mitigation:**
  - `SESSION_COOKIE_HTTPONLY = True` blocks JavaScript access.
  - `SESSION_COOKIE_AGE = 7200` (2-hour inactivity expiration).
  - `SESSION_SAVE_EVERY_REQUEST = True` continuously refreshes sliding window.
  - In production (`DEBUG=False`), `SESSION_COOKIE_SECURE = True` enforces HTTPS transmission only.
- **Remaining Risk:** Compromised end-user machine browser storage.
- **Accepted?** Yes; endpoint malware cannot be prevented by web server cookies.

### 5. Unauthorized Direct File Access
- **Scenario:** Attacker requests static/media URLs like `/media/vault_docs/confidential.pdf` bypassing authentication.
- **Impact:** Total bypass of access control.
- **Mitigation:** Private document storage is configured using `PrivateFileSystemStorage(base_url=None)`. Confidential files are stored in `private_media/` which is outside `STATIC_ROOT` and `MEDIA_URL` is completely absent from Django configuration. All file delivery occurs via `serve_secure_file()`.
- **Verification:** `documents/storage.py` overrides `.url()` to raise `SuspiciousFileOperation`.
- **Remaining Risk:** None.

### 6. Reuse of Revoked Links
- **Scenario:** A user who was previously granted access bookmarks a download link and tries to download the file after the owner revokes their permission.
- **Impact:** Continued unauthorized document leakage.
- **Mitigation:** TrustVault issues **no signed URLs or permanent links**. The download endpoint `/api/documents/{id}/download/` rechecks active permissions directly in the database (`has_active_document_permission()`) on every request.
- **Verification:** `MasterTrustVaultSecurityTests.test_12_13_14_immediate_revocation_enforced`.
- **Remaining Risk:** None.

### 7. Public Media Directory Exposure
- **Scenario:** Misconfiguration where web servers (Nginx/Apache) automatically serve private file directories.
- **Impact:** Mass document leakage without authorization.
- **Mitigation:** Nginx configuration explicitly forbids serving `private_media/` directly. Files are strictly opened by Python via `FileResponse` streams after authorization.
- **Remaining Risk:** None when deployed with provided Nginx configuration.

### 8. Path Traversal Attacks
- **Scenario:** Attacker uploads files with names like `../../../../etc/passwd` to overwrite system files or access arbitrary filesystem paths.
- **Impact:** System compromise or arbitrary file overwrite.
- **Mitigation:** `sanitize_filename()` strips all path components using `os.path.basename`, eliminates `..`, `/`, `\`, and null bytes. In storage, files are assigned randomized UUID names in dedicated subfolders.
- **Verification:** `documents/tests.py:test_path_traversal_filename_sanitized`.
- **Remaining Risk:** None.

### 9. Malicious File Uploads
- **Scenario:** Attacker uploads PHP, executable, or script files (`malware.exe`, `shell.php`) to achieve remote code execution.
- **Impact:** Complete server takeover.
- **Mitigation:** Multi-tier upload validation in `documents/validators.py`:
  1. Strict extension whitelist (`ALLOWED_FILE_EXTENSIONS`).
  2. Executable header detection (rejects `MZ`, `\x7fELF`, etc.).
  3. No uploads are executable on the filesystem.
- **Verification:** `documents/tests.py:test_executable_extension_rejected`.
- **Remaining Risk:** Zero-day file format exploits.
- **Accepted?** Yes; documents are not parsed or rendered on the server side.

### 10. MIME Type Spoofing
- **Scenario:** Attacker renames `malware.exe` to `report.pdf` and sends `Content-Type: application/pdf`.
- **Impact:** Bypassing extension filters.
- **Mitigation:** Content magic bytes inspection. PDF files must begin with `%PDF-`, PNG with `\x89PNG`, DOCX/XLSX with `PK\x03\x04`. Executable signatures trigger immediate rejection regardless of declared extension.
- **Verification:** `documents/tests.py:test_magic_bytes_mismatch_rejected`.
- **Remaining Risk:** None.

### 11. Double-Extension Attacks
- **Scenario:** Attacker uploads `invoice.pdf.exe` or `contract.docx.php` hoping naive splitters only inspect the first extension.
- **Impact:** Code execution on misconfigured servers.
- **Mitigation:** `validators.py` splits the entire filename across all dots and verifies that no intermediate component matches dangerous extension tokens.
- **Verification:** `documents/tests.py:test_double_extension_attack_rejected`.
- **Remaining Risk:** None.

### 12. SQL Injection (SQLi)
- **Scenario:** Attacker inputs `' OR 1=1 --` into search bars or permission fields.
- **Impact:** Unauthorized data exfiltration or database corruption.
- **Mitigation:** Django ORM uses parameterized queries with prepared statements across all database interactions. No raw SQL queries or string concatenations are used.
- **Remaining Risk:** None.

### 13. Cross-Site Scripting (XSS)
- **Scenario:** Attacker enters `<script>alert('XSS')</script>` into document title or description.
- **Impact:** Session hijacking or client-side execution.
- **Mitigation:**
  - Django template engine auto-escapes all context variables.
  - HTTP headers include `SECURE_CONTENT_TYPE_NOSNIFF = True` and `X_FRAME_OPTIONS = 'DENY'`.
  - Text uploads inspected for script tags.
- **Remaining Risk:** None.

### 14. Cross-Site Request Forgery (CSRF)
- **Scenario:** Attacker crafts a malicious site that triggers permission grant or revocation actions on behalf of an authenticated victim.
- **Impact:** Unauthorized permission changes.
- **Mitigation:** Django `CsrfViewMiddleware` is active. Every POST form requires a valid `{% csrf_token %}` validated against the user's session cookie.
- **Verification:** Handled natively by Django middleware.
- **Remaining Risk:** None.

### 15. Brute-Force Login Attacks
- **Scenario:** Automated password guessing against user accounts.
- **Impact:** Account compromise.
- **Mitigation:**
  - Every failed login attempt is recorded in the immutable audit trail with actor, IP, and timestamp.
  - Automated heuristic threshold triggers `SecurityEvent` when repeated failed attempts are detected.
  - In production, Nginx or cloud firewall (Cloudflare) rate limiting is deployed.
- **Remaining Risk:** Distributed brute-force from rotating botnets.
- **Accepted?** Yes; handled at perimeter network layer.

### 16. Password Attacks
- **Scenario:** Attacker attempts weak, dictionary, or common passwords.
- **Impact:** Credential theft.
- **Mitigation:** Django `AUTH_PASSWORD_VALIDATORS` enforces minimum length (8 chars), attribute dissimilarity, numeric presence, and common password blocklists. Passwords hashed using PBKDF2 with SHA-256 and unique salts.
- **Remaining Risk:** User choosing weak passwords outside standard dictionary.
- **Accepted?** Standard enterprise risk.

### 17. Audit Log Tampering
- **Scenario:** A rogue insider or compromised account modifies past audit records to conceal illicit access.
- **Impact:** Loss of forensic accountability and regulatory compliance.
- **Mitigation:**
  1. Append-only model enforcement: `AuditLog.save()` and `AuditLog.delete()` raise `PermissionDenied` if invoked on existing records.
  2. Cryptographic hash chain: each record binds `current_hash = SHA256(previous_hash + canonical_event_data)`.
  3. Continuous verification endpoint `/api/admin/audit/verify/` validates the entire hash chain.
- **Verification:** `audit/tests.py:test_audit_records_are_append_only_and_immutable`, `test_hash_chain_detects_tampering`.
- **Remaining Risk:** A superuser with direct root access to the database storage file rewriting the entire database and recalculating hashes.
- **Accepted?** Mitigated by external encrypted backups and remote syslog streaming recommendations.

### 18. Permission Race Conditions
- **Scenario:** Concurrent requests to grant and revoke access result in inconsistent active permission state.
- **Impact:** Phantom permissions remaining active after revocation.
- **Mitigation:**
  - All permission operations use `transaction.atomic()` with database row locking (`select_for_update()`).
  - Database-level partial unique constraint `UniqueConstraint(fields=['document', 'user'], condition=Q(is_active=True))` guarantees at most one active grant per document-user pair.
- **Verification:** `MasterTrustVaultSecurityTests.test_27_duplicate_active_permissions_prevented`.
- **Remaining Risk:** None.

### 19. Information Leakage Through Search
- **Scenario:** Unauthorized users search for document names or metadata and discover titles of confidential documents they cannot access.
- **Impact:** Metadata privacy breach.
- **Mitigation:** The search view strictly queries `get_accessible_documents_queryset(user)` which joins on ownership and active permissions *before* applying search filters. Unauthorized documents are never returned.
- **Verification:** `MasterTrustVaultSecurityTests.test_17_search_does_not_leak_unauthorized_documents`.
- **Remaining Risk:** None.

### 20. Information Leakage Through Error Responses
- **Scenario:** System returns "Document exists but you lack permission" vs "Document does not exist", revealing document existence to attackers.
- **Impact:** Document reconnaissance and metadata disclosure.
- **Mitigation:** Document endpoints return standard generic 403 Forbidden or non-disclosing 404 responses without revealing sensitive filesystem or ownership clues.
- **Remaining Risk:** None.

### 21. Administrator Privilege Misuse
- **Scenario:** An administrator uses system oversight privileges to read or download confidential executive documents.
- **Impact:** Violation of executive confidentiality and zero-trust principles.
- **Mitigation:** Administrators **do not** automatically inherit document download permissions. `can_download_document(admin, doc)` evaluates to `False` unless the owner has explicitly granted them read/edit access.
- **Verification:** `MasterTrustVaultSecurityTests.test_26_administrator_cannot_download_confidential_document_by_default`.
- **Remaining Risk:** Direct database filesystem access by DBA.
- **Accepted?** Yes; handled via infrastructure controls.

### 22. Downloaded File Retention After Revocation
- **Scenario:** A user who downloaded a PDF keeps a local copy on their computer after permission is revoked.
- **Impact:** Information persists in the client's possession.
- **Mitigation:** TrustVault enforces immediate server-side revocation stopping any future downloads, revisions, or views. HTTP headers instruct browser caches: `Cache-Control: no-cache, no-store, must-revalidate`.
- **Remaining Risk:** Physical copy retained on client hard drive.
- **Accepted?** **Yes.** It is mathematically and physically impossible for any web server to delete bits already transmitted to an external client computer without invasive, untrusted client-side DRM.

### 23. Database Compromise
- **Scenario:** Attacker dumps the SQL database.
- **Impact:** Exposure of metadata and user credentials.
- **Mitigation:**
  - Passwords hashed with PBKDF2-SHA256 (cannot be reversed).
  - Document files are stored outside the database with random storage UUIDs.
  - Audit trail hash chain makes retroactive modification immediately detectable.
- **Remaining Risk:** Document metadata exposure.
- **Accepted?** Standard defense-in-depth posture.

### 24. Backup Exposure
- **Scenario:** Database backups stored in unencrypted S3 buckets are leaked.
- **Impact:** Historical data exposure.
- **Mitigation:** Production deployment documentation specifies GPG-encrypted database and media backups with separate encryption keys.
- **Remaining Risk:** Operational key management.
- **Accepted?** Managed by deployment procedures.

### 25. Denial of Service (DoS) Through Large Uploads
- **Scenario:** Attacker uploads gigabyte-sized files to exhaust server disk space and RAM.
- **Impact:** Server crashes and downtime.
- **Mitigation:**
  - `MAX_UPLOAD_SIZE = 25 * 1024 * 1024` (25 MB) enforced in validator.
  - Django `DATA_UPLOAD_MAX_MEMORY_SIZE` limits memory consumption.
- **Verification:** `MasterTrustVaultSecurityTests.test_22_23_24_upload_security_validations`.
- **Remaining Risk:** High volume of 24MB uploads.
- **Accepted?** Managed by disk quotas and user upload permissions.

### 26. Unauthorized API Access
- **Scenario:** Attacker targets REST API directly using cURL or Postman to bypass frontend controls.
- **Impact:** Direct data access.
- **Mitigation:** Every API endpoint in `config/api_urls.py` enforces DRF `permission_classes = [IsAuthenticated]` and executes the centralized authorization checks before returning any data.
- **Verification:** `MasterTrustVaultSecurityTests.test_16_api_bypass_prevention`.
- **Remaining Risk:** None.

### 27. Account Deactivation and Existing Session Abuse
- **Scenario:** An employee is terminated and deactivated in the admin console, but attempts to continue downloading documents using an existing session cookie.
- **Impact:** Post-termination data theft.
- **Mitigation:** All authorization functions (`can_view_document`, `can_download_document`, `can_edit_document`) check `user.is_active`. Deactivating a user immediately causes all permission checks to return `False`, even within an active session.
- **Verification:** `MasterTrustVaultSecurityTests.test_25_deactivated_user_blocked`.
- **Remaining Risk:** None.

### 28. Insecure Document Version Access
- **Scenario:** Attacker tries to download old document versions via `?version=1` hoping historical revisions lack authorization checks.
- **Impact:** Historical confidential data leak.
- **Mitigation:** The download service `serve_secure_file()` executes `can_download_document()` prior to inspecting or retrieving any version records.
- **Verification:** `MasterTrustVaultSecurityTests.test_07_unauthorized_users_cannot_download`.
- **Remaining Risk:** None.
