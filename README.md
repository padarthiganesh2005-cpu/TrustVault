# TrustVault – Secure Document Sharing with a Real Audit Trail

> **Snovasys Fresher Hiring Challenge 2026**  
> **Tagline:** *Secure Documents. Trusted Access. Complete Accountability.*

---

## 1. Executive Summary & Problem Statement

Modern document management systems suffer from a systemic design flaw: they treat security as an afterthought layered on top of ordinary CRUD applications. Typical platforms rely on **signed download links with multi-minute validity**, **client-side button hiding**, **unprotected public media storage folders**, and **static audit logs** vulnerable to silent database tampering.

When access is revoked in such systems:
- A user can continue downloading the confidential file using their active link until the token expires.
- Unlinkable download links expose corporate IP through browser history and network proxies.
- Administrators frequently possess blanket bypass permissions to view private executive and board files.
- Internal attackers can delete or rewrite audit logs to cover their tracks without detection.

**TrustVault** solves these vulnerabilities by implementing a **defense-in-depth, security-first architecture**:
1. **Zero-Trust Document Access:** Granular, document-level authorization evaluated on every single request.
2. **Immediate Access Revocation:** Direct database validation with zero reliance on signed URLs; access terminates the instant an owner revokes permission.
3. **Isolated Private File Storage:** Files are stored in non-public storage directories with randomized UUID keys, never served via public static/media URLs.
4. **Append-Only Cryptographic Audit Trail:** Blockchain-style SHA-256 hash chains (`current_hash = SHA256(previous_hash + canonical_event_data)`) render any database log tampering immediately detectable.
5. **Decoupled Administrator Role:** System administrators manage accounts and review security telemetry, but **cannot** download confidential document content by default without explicit owner authorization.

---

## 2. Key Features

- **Multi-Role Access Control (RBAC):** Three distinct roles: **Administrator**, **Document Owner**, and **Viewer**.
- **Document-Level Permissions:** Fine-grained `READ` (view/download) and `EDIT` (view/download/modify metadata/replace version) grants.
- **Immediate Server-Side Revocation:** Instant termination of server-side access upon revocation; tested against bookmarked URLs, downloads, and REST APIs.
- **Strict File Upload Validation:** Magic bytes content signature inspection (rejects Windows PE `MZ` or Linux `ELF` executables disguised as documents), double-extension rejection, directory traversal sanitization, and 25 MB size limits.
- **Tamper-Evident Hash-Chained Audit Ledger:** Real-time logging of logins, uploads, views, downloads, edits, permissions, and blocked unauthorized attempts with on-demand mathematical verification.
- **Automated Security Alerting:** Anomaly detection service flags brute-force login bursts and IDOR probing attempts.
- **Version Control & Soft Deletion:** Historical revisions tracked with SHA-256 integrity fingerprints; soft-deleted files retain recoverable audit trails for owners.
- **Enterprise Dark Navy UI:** Built with Bootstrap 5, custom CSS, and responsive dashboards tailored to each role.
- **Comprehensive REST API:** Complete Django REST Framework API with session authentication, pagination, and strict permission enforcement.

---

## 3. Technology Stack

- **Backend:** Python 3.12, Django 5.1, Django REST Framework 3.15, Gunicorn / uWSGI.
- **Database:** SQLite 3 (Production on PythonAnywhere / Local zero-config).
- **Security & Integrity:** Standard Library `hashlib` (SHA-256), `filetype` magic bytes engine, Django Password Hashing (PBKDF2-SHA256).
- **Frontend:** HTML5, CSS3, Bootstrap 5.3, Bootstrap Icons, Django Templates.
- **Testing:** Django TestCase, DRF APIClient, 40 automated security scenarios (100% pass rate).
- **Hosting & Deployment:** PythonAnywhere (Live WSGI + SQLite3), Docker & Docker Compose, Nginx reverse proxy.

---

## 4. Role Permission Matrix

| Capability / Action | Administrator | Document Owner | Permitted Editor | Permitted Viewer | Unauthorized User |
|---|:---:|:---:|:---:|:---:|:---:|
| **Access System Dashboard** | Yes (System Ops) | Yes (Owner Portal) | Yes (Viewer Portal) | Yes (Viewer Portal) | No (Redirect) |
| **Manage Users (Activate/Deactivate)** | Yes | No | No | No | No |
| **Upload New Documents** | Yes | Yes | No | No | No |
| **View Own Documents** | Yes | Yes | N/A | N/A | No |
| **View Permitted Documents** | Metadata Only* | Yes | Yes | Yes | No (403/404) |
| **Download Document Content** | No (Confidential)* | Yes | Yes | Yes | No (403 Blocked) |
| **Edit Document Metadata** | No | Yes | Yes | No | No (403 Blocked) |
| **Upload Version Replacement** | No | Yes | Yes | No | No (403 Blocked) |
| **Grant / Revoke Document Permissions**| No | Yes | No | No | No (403 Blocked) |
| **Soft-Delete Document** | No | Yes | No | No | No (403 Blocked) |
| **Restore Document** | No | Yes | No | No | No (403 Blocked) |
| **Inspect System Audit Trail** | Full Vault | Owned Docs Only | No | No | No (403 Blocked) |
| **Run Hash Chain Integrity Check** | Yes | No | No | No | No (403 Blocked) |

> **\*Zero-Trust Boundary:** An Administrator **cannot** automatically read or download confidential document contents merely because they are an administrator. Content access requires an explicit grant from the document owner.

---

## 5. Project Architecture & Directory Layout

```
TrustVault/
│
├── manage.py                     # Django CLI management utility
├── requirements.txt              # Production Python dependencies
├── .env.example                  # Environment configuration template
├── README.md                     # Master documentation & setup guide
├── THREATS.md                    # Threat model & 28 attack mitigations
├── PROMPTS.md                    # Dated AI engineering log
├── Dockerfile                    # Containerization configuration
├── docker-compose.yml            # Multi-container orchestration (TrustVault Web)
├── nginx.conf                    # Hardened reverse-proxy configuration
│
├── config/                       # Project Configuration
│   ├── settings.py               # Django settings, security headers, database logic
│   ├── urls.py                   # Master URL routing (Web + Admin)
│   ├── api_urls.py               # Centralized REST API routing (/api/...)
│   ├── wsgi.py                   # WSGI server entrypoint
│   └── asgi.py                   # ASGI server entrypoint
│
├── accounts/                     # Accounts & RBAC Identity
│   ├── models.py                 # CustomUser with ADMIN, OWNER, VIEWER roles
│   ├── forms.py                  # Login, registration, profile, admin forms
│   ├── serializers.py            # DRF serializers for user objects
│   ├── views.py                  # Auth views + REST API controllers
│   ├── urls.py                   # Account routing
│   └── tests.py                  # Auth & deactivation security tests
│
├── documents/                    # Document Management & Ingestion
│   ├── models.py                 # Document, DocumentCategory, DocumentVersion
│   ├── services.py               # Centralized Document Authorization Service
│   ├── storage.py                # PrivateFileSystemStorage (base_url=None)
│   ├── validators.py             # Magic bytes, extension, and traversal checks
│   ├── forms.py                  # Upload, edit, and version forms
│   ├── serializers.py            # Safe metadata serializers (no physical paths)
│   ├── views.py                  # Ingestion, detail, download, restore views
│   ├── urls.py                   # Document routing
│   ├── tests.py                  # File security & upload tests
│   └── test_security_mandatory.py# 27 mandatory hackathon security tests
│
├── sharing/                      # Sharing & Access Control
│   ├── models.py                 # DocumentPermission (UniqueConstraint active), PermissionHistory
│   ├── services.py               # Grant, update, immediate revocation service
│   ├── forms.py                  # Permission grant form
│   ├── serializers.py            # Sharing API serializers
│   ├── views.py                  # Sharing actions & API controllers
│   ├── urls.py                   # Sharing routing
│   └── tests.py                  # Immediate revocation & constraint tests
│
├── audit/                        # Cryptographic Audit Trail
│   ├── models.py                 # AuditLog (append-only), SecurityEvent
│   ├── middleware.py             # AuditRequestMiddleware (captures forensic IP/agent)
│   ├── services.py               # SHA-256 hash chain & verify_audit_chain()
│   ├── serializers.py            # Audit serializers
│   ├── views.py                  # Audit ledger dashboard & verification API
│   ├── urls.py                   # Audit routing
│   └── tests.py                  # Immutability & tampering detection tests
│
├── dashboard/                    # Role-Tailored Dashboards
│   ├── views.py                  # Admin, Owner, and Viewer portal views
│   └── urls.py                   # Dashboard routing
│
├── templates/                    # Enterprise HTML5 Templates
│   ├── base.html                 # Dark navy theme, responsive sidebar
│   ├── accounts/                 # Login, register, profile, user management
│   ├── dashboard/                # Admin, Owner, Viewer dashboards
│   ├── documents/                # List, detail, upload, edit
│   ├── audit/                    # Audit ledger, document audit, security events
│   └── errors/                   # 403, 404, 500 error templates
│
├── static/                       # Static Assets
│   ├── css/trustvault.css        # Enterprise dark navy styling
│   └── js/trustvault.js          # Client helpers, copy hash, tooltips
│
├── private_media/                # Isolated Document Storage (Never served directly)
│
└── docs/                         # Detailed Technical Documentation
    ├── API.md                    # REST API endpoint reference
    ├── DATABASE.md               # Schema specification & Mermaid ER diagram
    ├── SECURITY.md               # Security architecture & negative test proof
    ├── DEPLOYMENT.md             # Production setup with PythonAnywhere & SQLite3
    └── DEMO_SCRIPT.md            # 5-minute evaluation demonstration plan
```

---

## 6. Installation & Local Setup

### Prerequisites
- Python 3.11+ installed.
- Git installed.

### Step 1: Clone Repository
```bash
git clone https://github.com/padarthiganesh2005-cpu/trustvault.git
cd trustvault
```

### Step 2: Create and Activate Virtual Environment
```bash
# Windows
python -m venv .venv
.\.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run Database Migrations
```bash
python manage.py migrate
```

### Step 5: Seed Demo Accounts & Sample Vault Data
```bash
python manage.py seed_data
```

### Step 6: Start Local Development Server
```bash
python manage.py runserver
```
Visit `http://localhost:8000` in your web browser.

---

## 7. Demo Accounts & Credentials

The seed data script automatically creates test accounts representing all three roles with pre-populated documents and audit history:

| Role | Username | Password | Purpose |
|---|---|---|---|
| **Administrator** | `admin` | `AdminPass123!@#` | Platform oversight, audit verification, user management |
| **Document Owner A** | `alice_owner` | `OwnerPass123!@#` | Uploads financial docs, grants & revokes permissions |
| **Document Owner B** | `bob_owner` | `OwnerPass123!@#` | Uploads engineering docs, tests cross-tenant isolation |
| **Viewer A** | `charlie_viewer` | `ViewerPass123!@#` | Tests authorized view & download, tests post-revocation loss |
| **Viewer B** | `david_viewer` | `ViewerPass123!@#` | Tests IDOR blocked attempts and denied download logging |

---

## 8. Automated Testing & Negative Security Verification

TrustVault includes **40 automated tests** covering unit logic, integration flows, and all 27 mandatory hackathon security scenarios.

### Running the Test Suite
```bash
python manage.py test
```

### Test Output Verification:
```text
Creating test database for alias 'default'...
Found 40 test(s).
System check identified no issues (0 silenced).
........................................
----------------------------------------------------------------------
Ran 40 tests in 51.330s

OK
Destroying test database for alias 'default'...
```

### Deliberate Negative Test Verification:
As required by Section 18 of the specification, a deliberate negative test was executed by temporarily bypassing the authorization check in `documents/services.py` (`can_download_document = lambda *_: True`). The automated security test suite immediately caught the bypass and failed with `AssertionError: 200 != 403`, confirming that the tests actively verify the authorization boundary. Once the check was restored, the test passed with 100% success. Full details are recorded in [`docs/SECURITY.md`](file:///docs/SECURITY.md).

---

## 9. Five-Minute Evaluation Demonstration

Follow the step-by-step presentation script in [`docs/DEMO_SCRIPT.md`](file:///docs/DEMO_SCRIPT.md):
1. **0:00–0:30:** Introduce TrustVault zero-trust philosophy.
2. **0:30–1:15:** Log in as `alice_owner`, upload `Merger_Acquisition_TermSheet_Confidential.pdf`.
3. **1:15–2:00:** Grant `READ` access to `charlie_viewer`.
4. **2:00–2:40:** Log in as `charlie_viewer`, demonstrate authorized view and download.
5. **2:40–3:20:** Log in as `david_viewer`, attempt to paste Alice's document URL (demonstrating **403 Forbidden** IDOR block).
6. **3:20–4:00:** Log in as `alice_owner`, click **Revoke Access** on Charlie.
7. **4:00–4:30:** Log in as `charlie_viewer`, demonstrate that the old URL and direct API download return **403 Forbidden** immediately.
8. **4:30–5:00:** Log in as `admin`, show the chronological audit trail, point out the blocked attempts, and click **"Run Chain Integrity Check"** to demonstrate cryptographic proof.

---

## 10. Production Deployment

### Option A: PythonAnywhere Hosting (Live Cloud Deployment with SQLite3)

TrustVault is configured for instant production deployment on **PythonAnywhere** using embedded SQLite3 and WSGI:

1. **Clone Repo in PythonAnywhere Bash Console:**
   ```bash
   git clone https://github.com/padarthiganesh2005-cpu/trustvault.git
   cd trustvault
   ```
2. **Setup Virtual Environment:**
   ```bash
   python3.11 -m venv ~/.virtualenvs/trustvault-venv
   source ~/.virtualenvs/trustvault-venv/bin/activate
   pip install -r requirements.txt
   ```
3. **Configure Production `.env`:**
   ```ini
   SECRET_KEY=1*(dd4!-4m0-3$ksswf!iz5hn0_^o*lgd+uah@)!t(!$$gd6-)
   DEBUG=False
   ALLOWED_HOSTS=trustvault.pythonanywhere.com,localhost,127.0.0.1
   SECURE_SSL_REDIRECT=True
   CSRF_COOKIE_SECURE=True
   SESSION_COOKIE_SECURE=True
   ```
4. **Initialize Database & Static Assets:**
   ```bash
   python manage.py migrate
   python manage.py seed_data
   python manage.py collectstatic --noinput
   ```
5. **PythonAnywhere Web Tab Setup:**
   - Source directory: `/home/trustvault/TrustVault`
   - Virtualenv: `/home/trustvault/TrustVault/.venv`
   - Static files mapping: `/static/` -> `/home/trustvault/TrustVault/staticfiles`
   - *Security rule:* Do NOT map `/private_media/` in the static table!
   - Toggle **Force HTTPS** ON and click **Reload**.

### Option B: Containerized Deployment with Docker (SQLite3)

```bash
cp .env.example .env
docker compose up -d --build
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_data
docker compose exec web python manage.py collectstatic --noinput
```

Health Check:
```bash
curl http://localhost/health/
# Response: {"status": "healthy", "service": "TrustVault", "version": "1.0.0"}
```

Complete step-by-step instructions for PythonAnywhere, Docker, and Ubuntu Linux are available in [`docs/DEPLOYMENT.md`](file:///docs/DEPLOYMENT.md).

---

## 11. Security Deliverables Summary

- **Threat Model:** [THREATS.md](file:///THREATS.md) (All 28 attack categories analyzed with mitigations).
- **AI Engineering Log:** [PROMPTS.md](file:///PROMPTS.md) (5 genuine dated entries with defects, review methods, and fixes).
- **API Reference:** [docs/API.md](file:///docs/API.md) (All REST endpoints documented).
- **Database Schema:** [docs/DATABASE.md](file:///docs/DATABASE.md) (Schema, Mermaid ER diagram, and concurrency locking).
- **Security Architecture:** [docs/SECURITY.md](file:///docs/SECURITY.md) (Cryptographic hash chaining and negative test proof).
- **Production Operations:** [docs/DEPLOYMENT.md](file:///docs/DEPLOYMENT.md) (PythonAnywhere SQLite3, Docker, Nginx, and Gunicorn).
- **Demonstration Plan:** [docs/DEMO_SCRIPT.md](file:///docs/DEMO_SCRIPT.md) (5-minute walkthrough script).
