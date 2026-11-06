# TrustVault REST API Documentation (docs/API.md)

TrustVault exposes a comprehensive, secure REST API built with Django REST Framework (DRF).

All endpoints require authentication unless explicitly marked as public. Every protected document interaction independently re-verifies document-level authorization against the database.

---

## 1. Authentication Endpoints

### `POST /api/auth/login/`
- **Purpose:** Authenticate user and initiate secure session.
- **Authentication:** None (Public).
- **Allowed Roles:** Any.
- **Request Body (JSON):**
  ```json
  {
    "username": "alice_owner",
    "password": "OwnerPass123!@#"
  }
  ```
- **Response Format (200 OK):**
  ```json
  {
    "id": 2,
    "username": "alice_owner",
    "email": "alice.owner@trustvault.local",
    "first_name": "",
    "last_name": "",
    "role": "OWNER",
    "role_display": "Document Owner",
    "department": "Finance & Executive Operations",
    "is_active": true,
    "date_joined": "2026-11-05T11:20:00Z"
  }
  ```
- **Error Codes:**
  - `400 Bad Request`: Missing username or password.
  - `401 Unauthorized`: Invalid credentials (logged as `USER_LOGIN_FAILED` in audit trail).
  - `403 Forbidden`: Account is deactivated.

### `POST /api/auth/logout/`
- **Purpose:** Securely terminate the authenticated session.
- **Authentication:** Required (Session).
- **Allowed Roles:** Any authenticated user.
- **Request Body:** None.
- **Response Format (200 OK):**
  ```json
  {
    "message": "Successfully logged out."
  }
  ```
- **Audit Event:** `USER_LOGOUT` (SUCCESS).

### `POST /api/auth/register/`
- **Purpose:** Self-register a new account (defaulting to Viewer or Owner).
- **Authentication:** None.
- **Request Body (JSON):**
  ```json
  {
    "username": "new_analyst",
    "email": "analyst@company.com",
    "password": "SecurePassword123!",
    "role": "VIEWER",
    "department": "Auditing"
  }
  ```
- **Response Format (201 Created):** User object without password hash.

---

## 2. User Management Endpoints

### `GET /api/users/`
- **Purpose:** List registered users (used by owners to select recipients for sharing).
- **Authentication:** Required.
- **Allowed Roles:**
  - `ADMIN`: Sees all active and deactivated accounts.
  - `OWNER` / `VIEWER`: Sees only active users to select sharing candidates.
- **Response Format (200 OK):** Array of User objects.

### `GET /api/users/me/`
- **Purpose:** Retrieve profile and role metadata for the current user.
- **Authentication:** Required.
- **Response Format (200 OK):** Current User object.

### `GET /api/users/{id}/`
- **Purpose:** Retrieve specific user profile details.
- **Permissions:** Admin or self only.

---

## 3. Document Management Endpoints

### `GET /api/documents/`
- **Purpose:** List authorized documents.
- **Authentication:** Required.
- **Confidentiality Rule:** Queryset strictly excludes unauthorized documents.
- **Query Parameters:**
  - `q` (string): Text search across title, description, and tags.
  - `category` (UUID): Filter by category ID.
- **Response Format (200 OK):**
  ```json
  [
    {
      "id": "e4b6c310-91a7-4c7b-b384-5f2fa6be1cb7",
      "name": "Q3 Financial Audit & Ledger",
      "description": "Verified Q3 financial ledger detailing company expenditures.",
      "category": "893c5240-20ba-449e-ba2e-3367c3b281ad",
      "category_name": "Financial Reports",
      "tags": "finance, audit, q3, confidential",
      "tag_list": ["finance", "audit", "q3", "confidential"],
      "file_type": "application/pdf",
      "file_extension": ".pdf",
      "file_size": 184320,
      "formatted_size": "180.0 KB",
      "file_hash": "a1b2c3d4e5f6...",
      "owner": 2,
      "owner_username": "alice_owner",
      "version": 1,
      "is_deleted": false,
      "created_at": "2026-11-05T11:20:00Z",
      "updated_at": "2026-11-05T11:20:00Z",
      "download_url": "/api/documents/e4b6c310-91a7-4c7b-b384-5f2fa6be1cb7/download/"
    }
  ]
  ```

### `POST /api/documents/`
- **Purpose:** Upload and ingest a new confidential document into private storage.
- **Authentication:** Required.
- **Allowed Roles:** `OWNER`, `ADMIN`.
- **Content-Type:** `multipart/form-data`.
- **Request Fields:**
  - `file` (binary, required): Max 25 MB.
  - `name` (string, required): Document title.
  - `description` (string, optional): Summary.
  - `category` (UUID, optional): Category ID.
  - `tags` (string, optional): Comma-separated tags.
- **Validation:** Enforces magic byte inspection, double extension checks, and file size limits.
- **Response Format (201 Created):** Full document detail object.

### `GET /api/documents/{id}/`
- **Purpose:** Retrieve metadata, version history, and permission roster for a document.
- **Authorization Check:** `can_view_document(user, document)`.
- **Error Codes:**
  - `403 Forbidden`: User has no active grant on this document (triggers `UNAUTHORIZED_ACCESS_ATTEMPT` audit log).
  - `404 Not Found`: Invalid document UUID.

### `PATCH /api/documents/{id}/`
- **Purpose:** Update document metadata (title, description, tags, category).
- **Authorization Check:** `can_edit_document(user, document)` (Owner or active `EDIT` permission).
- **Error Codes:** `403 Forbidden` if user is read-only viewer.

### `DELETE /api/documents/{id}/`
- **Purpose:** Soft-delete document (retained for owner restoration).
- **Authorization Check:** `can_delete_document(user, document)` (Owner only).
- **Audit Event:** `DOCUMENT_DELETE` (SUCCESS).

### `POST /api/documents/{id}/restore/`
- **Purpose:** Restore a soft-deleted document.
- **Authorization Check:** `can_restore_document(user, document)` (Owner only).
- **Audit Event:** `DOCUMENT_RESTORE` (SUCCESS).

### `GET /api/documents/{id}/download/`
- **Purpose:** Dedicated secure document download stream.
- **Authorization Check:** `can_download_document(user, document)` (Owner or active `READ`/`EDIT` grant).
- **Query Parameters:**
  - `version` (int, optional): Download specific historical revision.
- **Behavior:**
  - If unauthorized: Returns `403 Forbidden` and records `UNAUTHORIZED_DOWNLOAD_ATTEMPT` in the tamper-evident audit trail.
  - If authorized: Records `DOCUMENT_DOWNLOAD` (SUCCESS) and streams file with `X-Content-Type-Options: nosniff` and `Cache-Control: no-cache, no-store`.

---

## 4. Sharing & Permissions Endpoints

### `GET /api/documents/{id}/permissions/`
- **Purpose:** List all active and historical permission grants for a document.
- **Authorization:** Document Owner or Administrator only.
- **Response Format (200 OK):**
  ```json
  [
    {
      "id": "7f8b9c0d-1e2f-4a5b-8c9d-0e1f2a3b4c5d",
      "document": "e4b6c310-91a7-4c7b-b384-5f2fa6be1cb7",
      "user": 4,
      "user_username": "charlie_viewer",
      "user_email": "charlie.viewer@trustvault.local",
      "permission_type": "READ",
      "permission_type_display": "Read & Download",
      "granted_by": 2,
      "granted_by_username": "alice_owner",
      "is_active": true,
      "granted_at": "2026-11-05T11:22:00Z"
    }
  ]
  ```

### `POST /api/documents/{id}/permissions/`
- **Purpose:** Grant `READ` or `EDIT` permission to a registered user.
- **Authorization:** Document Owner only.
- **Request Body (JSON):**
  ```json
  {
    "user_id": 4,
    "permission_type": "READ"
  }
  ```
- **Response Format (201 Created):** Created permission object.
- **Audit Event:** `PERMISSION_GRANTED` (SUCCESS).

### `PATCH /api/permissions/{id}/`
- **Purpose:** Change permission level between `READ` and `EDIT`.
- **Authorization:** Document Owner only.
- **Request Body (JSON):**
  ```json
  {
    "permission_type": "EDIT"
  }
  ```
- **Response Format (200 OK):** Updated permission object.
- **Audit Event:** `PERMISSION_CHANGED` (SUCCESS).

### `DELETE /api/permissions/{id}/`
- **Purpose:** Immediately revoke document permission.
- **Authorization:** Document Owner only.
- **Behavior:**
  - Sets `is_active = False` in database within atomic transaction.
  - Records `PERMISSION_REVOKED` in audit trail.
  - Access stops working immediately on all subsequent requests.
- **Response Format (200 OK):**
  ```json
  {
    "message": "Permission successfully revoked with immediate effect."
  }
  ```

---

## 5. Audit & Forensic Endpoints

### `GET /api/audit/`
- **Purpose:** Query the append-only cryptographic audit trail.
- **Authorization:** Admin (all events) or Document Owner (events related to owned documents).
- **Query Parameters:**
  - `event_type`: Filter by event (e.g. `UNAUTHORIZED_ACCESS_ATTEMPT`).
  - `result`: Filter by `SUCCESS` or `DENIED`.
  - `document_id`: Filter by document UUID.
- **Response Format (200 OK):**
  ```json
  [
    {
      "id": "3b2a1c0d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
      "sequence_number": 19,
      "actor_username": "david_viewer",
      "actor_role": "VIEWER",
      "event_type": "UNAUTHORIZED_DOWNLOAD_ATTEMPT",
      "event_type_display": "Unauthorized Download Attempt",
      "document_id": "e4b6c310-91a7-4c7b-b384-5f2fa6be1cb7",
      "document_name": "Master Services Agreement Snovasys",
      "action_result": "DENIED",
      "ip_address": "192.168.1.142",
      "metadata": {
        "reason": "Access revoked by owner."
      },
      "timestamp": "2026-11-05T11:25:00Z",
      "previous_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "current_hash": "5d41402abc4b2a76b9719d911017c592..."
    }
  ]
  ```

### `POST /api/admin/audit/verify/`
- **Purpose:** Run cryptographic hash chain verification across all historical audit records.
- **Authorization:** Administrator only.
- **Response Format (200 OK):**
  ```json
  {
    "is_valid": true,
    "total_records": 19,
    "corrupted_at": null,
    "details": "All 19 audit records successfully verified. Cryptographic hash chain is intact."
  }
  ```

### `GET /api/admin/security-events/`
- **Purpose:** List high-priority automated security alerts (brute force bursts, IDOR probes).
- **Authorization:** Administrator only.

---

## 6. Dashboard Metrics Endpoints

- `GET /api/dashboard/admin/`: System-wide KPI metrics, user stats, upload/download counts, security alert totals.
- `GET /api/dashboard/owner/`: Document owner stats (uploaded, active grants, recent downloads, denied attempts).
- `GET /api/dashboard/viewer/`: Viewer catalog of shared documents with permission levels and download URLs.
