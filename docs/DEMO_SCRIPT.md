# Five-Minute Live Demonstration Script (docs/DEMO_SCRIPT.md)

**Project:** TrustVault – Secure Document Sharing with a Real Audit Trail  
**Target Duration:** 5 Minutes (300 Seconds)  
**Primary Thesis to Prove:**  
*"A user who has not been granted access cannot reach a document through any route, every access attempt is recorded in a tamper-evident audit trail, and revoking access immediately blocks all subsequent server-side access."*

---

## Demo Accounts Quick Reference

| Role | Username | Password | Purpose in Demo |
|---|---|---|---|
| **Document Owner** | `alice_owner` | `OwnerPass123!@#` | Uploads confidential doc, grants & revokes access |
| **Viewer A (Authorized then Revoked)** | `charlie_viewer` | `ViewerPass123!@#` | Downloads doc, then loses access immediately |
| **Viewer B (Unauthorized / Attacker)** | `david_viewer` | `ViewerPass123!@#` | Demonstrates IDOR probing & blocked access |
| **Administrator** | `admin` | `AdminPass123!@#` | Demonstrates audit chain verification & security alerts |

---

## Minute-by-Minute Walkthrough

### 0:00 – 0:30: Introduction & Problem Statement
- **Narrator Action:** Open the TrustVault login screen (`http://localhost:8000/login/`).
- **Speaking Points:**
  - *"Welcome. Most document sharing platforms rely on security-by-obscurity, long-lived pre-signed download URLs, and weak authorization. Once a link is leaked or access is revoked, stale permissions and cached tokens often still allow data exfiltration."*
  - *"TrustVault is built from the ground up on zero-trust principles: private isolated file storage, database-enforced permissions on every download request, immediate server-side revocation, and a blockchain-style SHA-256 cryptographic audit trail."*

### 0:30 – 1:15: Owner Login & Confidential Document Ingestion
- **Narrator Action:**
  1. Log in as `alice_owner` (`OwnerPass123!@#`).
  2. The Owner Portal loads showing uploaded documents and stats.
  3. Click **"Upload New Document"** (`/documents/upload/`).
  4. Fill in:
     - Title: `Merger_Acquisition_TermSheet_Confidential.pdf`
     - Category: `Financial Reports`
     - Tags: `m&a, confidential, acquisition`
     - File: Choose a sample PDF.
  5. Click **"Ingest & Secure Document"**.
- **Speaking Points:**
  - *"Notice the file is automatically inspected for magic bytes signatures and stored in server-private storage with a randomized UUID path. It has no public media URL."*
  - *"A SHA-256 integrity fingerprint is calculated and sealed into our append-only audit trail."*

### 1:15 – 2:00: Granting Granular Read Permission
- **Narrator Action:**
  1. From the document detail page, scroll to the **"Grant Document Access"** card.
  2. Select User: `charlie_viewer`.
  3. Select Permission: `Read & Download`.
  4. Click **"Authorize User"**.
- **Speaking Points:**
  - *"Alice grants Charlie read-only access. Notice our database-backed permission model creates an active grant and immediately records a `PERMISSION_GRANTED` event in the audit ledger."*
  - *"Copy the document URL (e.g. `http://localhost:8000/documents/{uuid}/`)."*
  - Click **Sign Out**.

### 2:00 – 2:40: Viewer A Authorized Access & Download
- **Narrator Action:**
  1. Log in as `charlie_viewer` (`ViewerPass123!@#`).
  2. The Viewer Portal displays `Merger_Acquisition_TermSheet_Confidential.pdf` in the **"Shared With Me"** table.
  3. Click **"Download"**.
  4. The browser downloads the file cleanly.
- **Speaking Points:**
  - *"Charlie is authenticated and authorized. The server streams the file directly with `nosniff` and `no-store` headers, and logs a successful `DOCUMENT_DOWNLOAD` event."*
  - Click **Sign Out**.

### 2:40 – 3:20: Viewer B Denied Access (IDOR Probing Demonstration)
- **Narrator Action:**
  1. Log in as `david_viewer` (`ViewerPass123!@#`).
  2. Notice that David's portal does **not** list Alice's confidential document.
  3. In the browser address bar, paste Alice's document URL (`/documents/{uuid}/`) or directly call `/api/documents/{uuid}/download/`.
  4. The server immediately returns **403 Forbidden: Access Denied**.
- **Speaking Points:**
  - *"David attempts an IDOR attack by pasting the direct document ID. The centralized authorization service checks the database, finds no active grant for David, blocks the request with 403 Forbidden, and flags an unauthorized access attempt in the security ledger."*
  - Click **Sign Out**.

### 3:20 – 4:00: Immediate Access Revocation by Owner
- **Narrator Action:**
  1. Log in as `alice_owner` (`OwnerPass123!@#`).
  2. Open the document detail page for `Merger_Acquisition_TermSheet_Confidential.pdf`.
  3. In the **"Active Authorizations"** table, locate `charlie_viewer`.
  4. Click the red **"Revoke"** button and confirm the prompt.
- **Speaking Points:**
  - *"Alice immediately revokes Charlie's access. The revocation is applied atomically in the database (`is_active = False`). There are no cached tokens or valid pre-signed URLs."*
  - Click **Sign Out**.

### 4:00 – 4:30: Proving Immediate Revocation for Viewer A
- **Narrator Action:**
  1. Log back in as `charlie_viewer` (`ViewerPass123!@#`).
  2. Notice the document has vanished from Charlie's **"Shared With Me"** catalog.
  3. Paste the old document URL into the browser or click a bookmarked download link.
  4. The server instantly denies the request: **403 Forbidden**.
- **Speaking Points:**
  - *"Charlie attempts to use the exact URL that worked 2 minutes ago. The server re-evaluates authorization in real-time, finds the permission revoked, and blocks the request immediately. This proves zero-lag access revocation."*
  - Click **Sign Out**.

### 4:30 – 5:00: Cryptographic Audit Trail & Admin Dashboard
- **Narrator Action:**
  1. Log in as `admin` (`AdminPass123!@#`).
  2. Open the **"Audit Trail"** (`/audit/`).
  3. Point out the sequence of recorded events:
     - `DOCUMENT_UPLOAD` by Alice
     - `PERMISSION_GRANTED` to Charlie
     - `DOCUMENT_DOWNLOAD` by Charlie (SUCCESS)
     - `UNAUTHORIZED_ACCESS_ATTEMPT` by David (DENIED)
     - `PERMISSION_REVOKED` from Charlie
     - `UNAUTHORIZED_DOWNLOAD_ATTEMPT` by Charlie (DENIED)
  4. Click **"Run Chain Integrity Check"**.
  5. The green verification banner appears: *"All audit records successfully verified. Cryptographic hash chain is intact."*
- **Speaking Points:**
  - *"Every action—both permitted downloads and blocked attacks—is permanently recorded. Every record is chained using SHA-256: `current_hash = SHA256(previous_hash + canonical_event_data)`. Any retroactive modification breaks the chain instantly."*
  - *"This delivers complete accountability and airtight compliance."*
