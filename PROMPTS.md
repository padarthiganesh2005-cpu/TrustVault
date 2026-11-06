# TrustVault AI Usage Documentation (PROMPTS.md)

This log records the genuine, iterative development interactions with AI assistants throughout the architecture, implementation, and security hardening of **TrustVault**. It documents discovered defects, review methodologies, architectural corrections, and verification links.

---

### Entry 1: Zero-Trust Document Authorization & Immediate Revocation Architecture
- **Date:** 2026-11-05
- **Prompt / Request Summary:**
  > "Design the centralized document authorization service in `documents/services.py` and permission checking logic. Ensure that document owners can grant and revoke permissions, and that Administrators have oversight of the platform without automatically reading every confidential document."
- **What the AI Initially Generated:**
  A helper function where `is_staff` or `is_admin_role` was granted blanket `True` across all checks:
  ```python
  def can_download_document(user, document):
      if user.is_admin_role or document.owner == user:
          return True
      return user.has_perm('can_download')
  ```
  Additionally, permissions were checked against session variables or user role claims.
- **What Was Specifically Incorrect or Incomplete:**
  1. **Confidentiality Breach:** The hackathon specification explicitly mandates that an Administrator *cannot* automatically read every confidential document merely because they are an administrator. Granting admins automatic download capability violates the zero-trust boundary.
  2. **Stale Revocation:** Relying on session flags or cached permission objects allows a revoked user to continue downloading until their session expires, violating the **immediate revocation** requirement.
- **How the Implementation Was Reviewed:**
  Code review evaluated Section 4.A ("Cannot automatically read every confidential document merely because they are an administrator") and Section 7 ("Immediate Access Revocation").
- **What Was Changed or Implemented Instead:**
  1. Refactored `can_download_document(user, document)` to strictly require that the user is either the **document owner** or has an **active** `DocumentPermission` record in the database.
  2. Administrators are granted metadata visibility only (`can_view_document`) for system oversight, while download access requires an explicit grant or audited break-glass procedure.
  3. All download checks directly query the database (`DocumentPermission.objects.filter(..., is_active=True)`) with no intermediate caching.
- **Verification & Git Commit Reference:**
  - Implemented in `documents/services.py` and `sharing/services.py`.
  - Tested in `MasterTrustVaultSecurityTests.test_12_13_14_immediate_revocation_enforced` and `test_26_administrator_cannot_download_confidential_document_by_default`.
  - Version Reference: `commit-v1.0.1-auth-hardening`

---

### Entry 2: Cryptographic Audit Hash Chain & Deterministic Serialization
- **Date:** 2026-11-05
- **Prompt / Request Summary:**
  > "Implement an append-only, tamper-evident audit logging service in `audit/services.py` using SHA-256 hash chaining `current_hash = SHA256(previous_hash + canonical_event_data)` and a verification function."
- **What the AI Initially Generated:**
  A hashing routine that stringified the audit dictionary using standard `str(dict)`:
  ```python
  def compute_record_hash(prev_hash, record):
      data = f"{prev_hash}{record.event_type}{record.timestamp}"
      return hashlib.sha256(data.encode()).hexdigest()
  ```
  The model's verification loop re-read Python `datetime` objects and compared stringified dates.
- **What Was Specifically Incorrect or Incomplete:**
  1. **Non-Deterministic Serialization:** Python dictionaries do not guarantee deterministic serialization across different platforms or JSON parsers if separators and sorting are omitted.
  2. **Timestamp Jitter:** Microsecond resolution differences between database serialization and Python memory caused hash verification failures during tests.
  3. **Incomplete Canonical Data:** Crucial forensic fields like `actor_username`, `document_id`, `action_result`, and `ip_address` were omitted from the hashed payload, meaning an attacker could tamper with IP addresses without breaking the hash chain!
- **How the Implementation Was Reviewed:**
  Ran `audit/tests.py` to verify hash reproducibility across multiple records.
- **What Was Changed or Implemented Instead:**
  1. Created `canonicalize_event_payload()` using `json.dumps(..., sort_keys=True, separators=(',', ':'))`.
  2. Explicitly bound all forensic parameters (`sequence_number`, `actor`, `event_type`, `document_id`, `target`, `action_result`, `ip_address`, `timestamp_iso`, `metadata`) into the hash calculation.
  3. Stored the canonical ISO timestamp `_canonical_ts` inside the audit entry's metadata to guarantee 100% deterministic recalculation.
  4. Added `select_for_update()` inside `transaction.atomic()` to guarantee monotonic sequence incrementing.
- **Verification & Git Commit Reference:**
  - Implemented in `audit/services.py` and `audit/models.py`.
  - Tested in `audit/tests.py:test_hash_chain_continuity_and_verification` and `test_hash_chain_detects_tampering`.
  - Version Reference: `commit-v1.0.2-audit-chain-deterministic`

---

### Entry 3: Secure File Upload Validation & Binary Signature Verification
- **Date:** 2026-11-05
- **Prompt / Request Summary:**
  > "Implement file upload validation in `documents/validators.py` to prevent malware, path traversal, double-extension attacks, and malicious uploads."
- **What the AI Initially Generated:**
  A validator that inspected only the file extension and the HTTP request's `Content-Type` header:
  ```python
  def validate_file_upload(file):
      ext = file.name.split('.')[-1]
      if ext not in ['pdf', 'docx', 'png']:
          raise ValidationError("Invalid extension")
      if file.content_type not in ['application/pdf', 'image/png']:
          raise ValidationError("Invalid mime")
  ```
- **What Was Specifically Incorrect or Incomplete:**
  1. **Trivial MIME Spoofing:** The `Content-Type` header is supplied by the client and can be spoofed by any attacker using cURL or Burp Suite.
  2. **Double-Extension Blindspot:** `file.name.split('.')[-1]` accepts files like `exploit.exe.pdf`.
  3. **Executable Payload Signature Absence:** An executable renamed to `.pdf` would pass both extension and client-provided MIME checks.
- **How the Implementation Was Reviewed:**
  Tested with a mock binary payload containing Windows PE header `b"MZ\x90..."` named `invoice.pdf`.
- **What Was Changed or Implemented Instead:**
  1. Implemented file header inspection (`file_obj.read(2048)`) checking magic bytes:
     - PDF must start with `%PDF-`.
     - PNG must start with `\x89PNG\r\n\x1a\n`.
     - JPEG must start with `\xff\xd8\xff`.
     - OpenXML (DOCX, XLSX) must start with `PK\x03\x04`.
  2. Added immediate rejection if file begins with binary executable signatures (`MZ`, `\x7fELF`, `\xca\xfe\xba\xbe`).
  3. Added multi-extension inspection iterating over all dot-separated segments to catch `dangerous.exe.pdf`.
  4. Enforced strict 25 MB file size limit and 0-byte empty file checks.
- **Verification & Git Commit Reference:**
  - Implemented in `documents/validators.py`.
  - Tested in `documents/tests.py:test_magic_bytes_mismatch_rejected` and `test_double_extension_attack_rejected`.
  - Version Reference: `commit-v1.0.3-file-security-hardening`

---

### Entry 4: Windows CP1252 Terminal Encoding & CLI Compatibility
- **Date:** 2026-11-05
- **Prompt / Request Summary:**
  > "Create the seed data management command `accounts/management/commands/seed_data.py` to populate test users, categories, documents, and sample audit history."
- **What the AI Initially Generated:**
  A management command that wrote formatted output using Unicode checkmark characters:
  ```python
  self.stdout.write(self.style.SUCCESS("✓ Demo users created successfully."))
  ```
- **What Was Specifically Incorrect or Incomplete:**
  When executed on a standard Windows PowerShell environment, the default stdout encoding is `cp1252`, which does not define the character `\u2713`. Running the command crashed with:
  `UnicodeEncodeError: 'charmap' codec can't encode character '\u2713' in position 0: character maps to <undefined>`.
- **How the Implementation Was Reviewed:**
  Direct execution of `python manage.py seed_data` in terminal environment revealed the exception.
- **What Was Changed or Implemented Instead:**
  Replaced all non-ASCII Unicode glyphs with portable, robust ASCII status badges (`[OK]`, `[INFO]`, `[FAIL]`), ensuring zero-dependency cross-platform execution on Windows, Linux, and macOS.
- **Verification & Git Commit Reference:**
  - Fixed in `accounts/management/commands/seed_data.py`.
  - Command executes cleanly with code 0 on Windows PowerShell and Linux Docker containers.
  - Version Reference: `commit-v1.0.4-cli-encoding-portability`

---

### Entry 5: REST API URL Routing Architecture & DRF Authentication Status Codes
- **Date:** 2026-11-05
- **Prompt / Request Summary:**
  > "Configure DRF REST API routing according to the specification in Section 16, and run the automated security test suite."
- **What the AI Initially Generated:**
  API endpoints were placed inside each individual app's `urls.py` and included in `config/urls.py` under the app namespace (e.g. `path('documents/', include('documents.urls'))`). This resulted in API paths like `/documents/api/documents/<id>/download/`.
  In tests, unauthenticated API requests were asserted strictly for `401 Unauthorized`.
- **What Was Specifically Incorrect or Incomplete:**
  1. The project specification strictly requires root-level API endpoints such as `/api/documents/`, `/api/auth/login/`, and `/api/dashboard/admin/`.
  2. In Django REST Framework, when `SessionAuthentication` is enabled without an active session cookie, DRF returns `403 Forbidden` rather than `401 Unauthorized` because SessionAuthentication does not challenge the client with a `WWW-Authenticate` header. Asserting `401` caused test failures.
  3. App directories lacked `__init__.py` files, causing Python 3.12's `unittest` module loader to throw an `ImportError` when discovering test files across multiple apps.
- **How the Implementation Was Reviewed:**
  Ran `python manage.py test` which surfaced 4 test failures.
- **What Was Changed or Implemented Instead:**
  1. Created a dedicated `config/api_urls.py` mounting all API endpoints directly under `/api/`.
  2. Updated tests to assert `assertIn(response.status_code, [401, 403])` representing rejected unauthenticated access.
  3. Added explicit `__init__.py` files across all application directories.
  4. Re-ran test suite: all 40 automated tests passed with 100% success.
- **Verification & Git Commit Reference:**
  - Implemented in `config/api_urls.py`, `config/urls.py`, and `documents/test_security_mandatory.py`.
  - Test Suite Result: 40 tests passed in 51.3s.
  - Version Reference: `commit-v1.0.5-api-routing-and-test-pass`
