# TrustVault Security Architecture & Implementation Guide (docs/SECURITY.md)

This document provides a comprehensive security review of **TrustVault – Secure Document Sharing with a Real Audit Trail**, explaining the security controls, cryptographic safeguards, and verification methodologies.

---

## 1. Zero-Trust Access Control Architecture

TrustVault operates under a **Zero-Trust Model**: no entity (internal user, network, or administrator) is implicitly trusted. Every request to inspect, edit, or download a document requires explicit, real-time authorization against the database.

### 1.1 The Role Permission Matrix

| Operation | Administrator | Document Owner | Permitted Editor | Permitted Viewer | Unauthorized User |
|---|:---:|:---:|:---:|:---:|:---:|
| **Access System Dashboard** | Yes | Yes (Owner portal) | Yes (Viewer portal) | Yes (Viewer portal) | No (Redirect to login) |
| **Manage Users & Accounts** | Yes | No | No | No | No |
| **Upload Documents** | Yes | Yes | No | No | No |
| **View Own Documents** | Yes | Yes | N/A | N/A | No |
| **View Permitted Documents** | Metadata only* | Yes | Yes | Yes | No (403/404) |
| **Download Document Content** | No (Unless granted)* | Yes | Yes | Yes | No (403 Blocked) |
| **Edit Document Metadata** | No | Yes | Yes | No | No (403 Blocked) |
| **Upload Version Replacement** | No | Yes | Yes | No | No (403 Blocked) |
| **Grant / Revoke Permissions** | No | Yes | No | No | No (403 Blocked) |
| **Soft-Delete Document** | No | Yes | No | No | No (403 Blocked) |
| **Restore Document** | No | Yes | No | No | No (403 Blocked) |
| **View Audit Trail** | Full Vault | Owned Documents | No | No | No (403 Blocked) |
| **Run Hash Verification** | Yes | No | No | No | No (403 Blocked) |

> **\*Critical Zero-Trust Boundary:** An Administrator **cannot** automatically read or download confidential document contents merely by virtue of their administrative role. Platform administration is strictly decoupled from document content confidentiality.

---

## 2. Centralized Document Authorization Service

All authorization decisions across both Django template views and Django REST Framework endpoints are evaluated through a single centralized service module: [`documents/services.py`](file:///documents/services.py).

### Core Authorization Functions:
- `can_view_document(user, document)`: Checks whether user is owner, has active READ/EDIT permission in DB, or is an administrator reviewing metadata.
- `can_download_document(user, document)`: Evaluates strictly whether user is document owner or holds an active READ or EDIT grant in the database. Returns `False` for administrators unless explicitly granted.
- `can_edit_document(user, document)`: Evaluates whether user is owner or holds an active EDIT grant.
- `can_delete_document(user, document)`: Strictly restricted to the document owner.
- `can_manage_permissions(user, document)`: Strictly restricted to the document owner.

---

## 3. Immediate Access Revocation Mechanism

Traditional cloud storage systems often rely on signed download URLs with multi-minute TTLs (e.g. AWS S3 presigned URLs valid for 15 minutes). If a document owner revokes a user's access, the user can still use the signed link until the token expires.

### How TrustVault Solves Immediate Revocation:
1. **No Long-Lived Pre-Signed URLs:** TrustVault issues **zero signed URLs**.
2. **Dynamic Database Checks on Every Request:** The dedicated download endpoint `/api/documents/{id}/download/` and the web download view execute a direct database query on every request:
   ```python
   DocumentPermission.objects.filter(
       document=document,
       user=user,
       is_active=True,
       permission_type__in=[PermissionType.READ, PermissionType.EDIT]
   ).exists()
   ```
3. **Atomic Revocation:** When an owner revokes access, `permission.is_active` is toggled to `False` inside an atomic transaction.
4. **Immediate Server-Side Termination:** If a revoked user attempts to refresh an old URL, download again, or call the REST API, the server detects `is_active=False` and immediately responds with `403 Forbidden`, logging an `UNAUTHORIZED_DOWNLOAD_ATTEMPT` in the audit ledger.

---

## 4. Cryptographic Hash Chain Audit Trail

To make the audit trail tamper-evident, TrustVault implements a **blockchain-style SHA-256 cryptographic hash chain**.

### 4.1 Mathematical Model
Every audit event record $N$ binds itself cryptographically to record $N-1$:
$$\text{current\_hash}_N = \text{SHA256}(\text{previous\_hash}_N \parallel \text{canonical\_payload}_N)$$

Where:
- $\text{previous\_hash}_1 = \text{"0"}^{64}$ (Genesis Block).
- $\text{previous\_hash}_N = \text{current\_hash}_{N-1}$ for $N > 1$.
- $\text{canonical\_payload}_N$ is the deterministic JSON serialization of the canonical tuple:
  $$(\text{seq}, \text{actor}, \text{event}, \text{doc\_id}, \text{target}, \text{result}, \text{ip}, \text{canonical\_ts}, \text{metadata})$$
  Serialized strictly with `json.dumps(..., sort_keys=True, separators=(',', ':'))`.

### 4.2 Tamper Evident Verification Algorithm
The verification service `verify_audit_chain()` sequentially traverses the entire database table from `sequence_number = 1` to `N`:
1. Validates monotonic continuity of sequence numbers ($seq_k = seq_{k-1} + 1$).
2. Validates that `previous_hash` strictly equals the `current_hash` of the preceding record.
3. Independently recomputes `SHA256(previous_hash + canonical_payload)` and checks exact equality against stored `current_hash`.
4. If an unauthorized actor attempts to alter any log entry (e.g., changing `DENIED` to `SUCCESS` or modifying an actor name), the hash of that record changes, breaking the cryptographic chain for all subsequent entries.

---

## 5. Deliberate Negative Security Test Verification

To satisfy hackathon requirements and scientifically prove that security tests are genuinely verifying authorization boundaries rather than false-positive assertions, a deliberate negative test was executed:

1. **Test Targeted:** `MasterTrustVaultSecurityTests.test_07_unauthorized_users_cannot_download`.
2. **Controlled Bypass Injected:**
   ```python
   def can_download_document(user, document: Document) -> bool:
       return True  # Deliberate negative bypass
   ```
3. **Execution Result:**
   ```
   FAIL: test_07_unauthorized_users_cannot_download
   AssertionError: 200 != 403
   Ran 1 test in 1.483s (FAILED failures=1)
   ```
4. **Code Restoration:** The secure database authorization check was restored.
5. **Re-Verification Result:**
   ```
   Ran 1 test in 1.483s
   OK
   ```
This confirms that the test harness actively catches authorization bypasses.

---

## 6. Private File Storage Architecture

```
Web Browser / API Client
          │
          │ 1. GET /api/documents/{id}/download/
          ▼
┌────────────────────────────────────────────────────────┐
│               TrustVault Backend Layer                 │
│                                                        │
│  [CsrfViewMiddleware] ──▶ [Authentication]             │
│                                │                       │
│                                ▼                       │
│                    can_download_document()?            │
│                       /               \                │
│                 No   /                 \  Yes          │
│                     ▼                   ▼              │
│               [403 Forbidden]     Stream Private File  │
│               Audit: DENIED       Audit: SUCCESS       │
└─────────────────────────────────────────┬──────────────┘
                                          │ 2. Safe Open
                                          ▼
                         ┌─────────────────────────────────┐
                         │   private_media/ (Isolated)     │
                         │   • vault_docs/{uuid}/{uuid}.ext│
                         │   • base_url = None             │
                         │   • Hidden from static/media    │
                         └─────────────────────────────────┘
```

1. **Storage Isolation:** Files are written to `settings.PRIVATE_MEDIA_ROOT` (`BASE_DIR / 'private_media'`).
2. **Zero Public URLs:** `base_url` is configured as `None`. Calling `file.url` raises a `SuspiciousFileOperation`.
3. **Streamed Content:** Files are read from disk exclusively by the Python process and piped into Django `FileResponse` objects with `nosniff` and `no-cache` headers.

---

## 7. Residual Risks & Security Limitations

1. **Offline Client Copies:** When an authorized user downloads a file, they hold a physical byte stream on their local disk. Server-side revocation terminates all subsequent server access, but cannot delete bits off client laptops without invasive client DRM.
2. **Direct Database Superuser Access:** An operator with raw root shell access to the database storage file could theoretically rewrite records and recalculate hashes. In production, this is mitigated by shipping audit logs to an immutable write-once (WORM) storage bucket or external syslog appliance (Datadog/Splunk).
