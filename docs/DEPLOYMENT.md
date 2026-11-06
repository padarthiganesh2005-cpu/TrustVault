# TrustVault Production Deployment & Operations Guide (docs/DEPLOYMENT.md)

This manual provides complete instructions for deploying **TrustVault** into production environments. TrustVault is designed for secure, lightweight, and robust operations powered by **SQLite3**.

---

## 1. Official Repository & Environment Specifications

- **GitHub Repository:** [https://github.com/padarthiganesh2005-cpu/trustvault.git](https://github.com/padarthiganesh2005-cpu/trustvault.git)
- **Production Database:** Embedded SQLite3 (`db.sqlite3` located at project root).
- **Production Secret Key:** `1*(dd4!-4m0-3$ksswf!iz5hn0_^o*lgd+uah@)!t(!$$gd6-)`
- **Supported Python Versions:** Python 3.11 or Python 3.12

---

## 2. PythonAnywhere Deployment Guide (Primary Cloud Target)

PythonAnywhere provides a managed Linux hosting environment with native WSGI process management, persistent block storage, and free automated HTTPS. TrustVault runs directly on PythonAnywhere using **SQLite3**, requiring zero external database configuration.

### Architecture on PythonAnywhere
```
Client (Browser / API)
       │ HTTPS
       ▼
PythonAnywhere Load Balancer / SSL Termination (X-Forwarded-Proto: https)
       │
       ▼
uWSGI Worker (/var/www/<username>_pythonanywhere_com_wsgi.py)
       │
       ├── /static/ ─────────▶ /home/<username>/TrustVault/staticfiles (Direct static mapping)
       │
       └── TrustVault Core (Django 5.1)
             ├── Database ───────▶ /home/<username>/TrustVault/db.sqlite3 (SQLite3 engine)
             └── Storage ────────▶ /home/<username>/TrustVault/private_media/ (Protected zero-trust storage)
```

---

### Step 1: Clone the GitHub Repository on PythonAnywhere

1. Log into your account at [https://www.pythonanywhere.com](https://www.pythonanywhere.com).
2. Go to the **Consoles** tab and start a new **Bash console**.
3. Clone your GitHub repository into your home directory:
   ```bash
   cd ~
   git clone https://github.com/padarthiganesh2005-cpu/trustvault.git TrustVault
   cd TrustVault
   ```

---

### Step 2: Create a Virtual Environment & Install Dependencies

In the same Bash console:

```bash
# Create a dedicated virtual environment with Python 3.12
python3.12 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip and install all production dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

### Step 3: Create the Production Environment File (`.env`)

Create `.env` in `/home/trustvault/TrustVault/.env`:

```bash
cat << 'EOF' > .env
SECRET_KEY=1*(dd4!-4m0-3$ksswf!iz5hn0_^o*lgd+uah@)!t(!$$gd6-)
DEBUG=False
ALLOWED_HOSTS=trustvault.pythonanywhere.com,localhost,127.0.0.1
SECURE_SSL_REDIRECT=True
CSRF_COOKIE_SECURE=True
SESSION_COOKIE_SECURE=True
EOF
```

---

### Step 4: Run Database Migrations, Seed Demo Accounts & Collect Static Assets

While still in `/home/trustvault/TrustVault` with your virtualenv activated:

```bash
# 1. Apply database migrations to create SQLite schema
python manage.py migrate

# 2. Seed default demo accounts, categories, and initial cryptographic audit genesis
python manage.py seed_data

# 3. Collect static assets into staticfiles/ for web serving
python manage.py collectstatic --noinput

# 4. Verify private storage directory permissions
mkdir -p private_media
chmod 700 private_media
```

---

### Step 5: Configure the PythonAnywhere "Web" Tab

1. Navigate to the **Web** tab on PythonAnywhere dashboard.
2. If creating a new web app:
   - Choose **Manual configuration** (do **NOT** select the automated Django wizard).
   - Select **Python 3.12**.
3. Under the **Code** section:
   - **Source code:** `/home/trustvault/TrustVault`
   - **Working directory:** `/home/trustvault/TrustVault`
4. Under the **Virtualenv** section:
   - Enter path: `/home/trustvault/TrustVault/.venv`
5. Under the **Static files** section:
   - **URL:** `/static/`
   - **Directory:** `/home/trustvault/TrustVault/staticfiles`
   - > [!CAUTION]
     > **CRITICAL ZERO-TRUST SECURITY RULE:**  
     > **DO NOT** add any entry for `/private_media/` or `/media/`!  
     > Files uploaded to TrustVault are stored in `private_media/` and must only be served through TrustVault's authenticated Django views (`/documents/<id>/download/`).
6. Under **Security**:
   - Turn **Force HTTPS** toggle to **ON**.

---

### Step 6: Configure the PythonAnywhere WSGI File

In the **Web** tab under **Code**, click on `/var/www/trustvault_pythonanywhere_com_wsgi.py`. Replace its contents with:

```python
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Define project home directory
project_home = Path('/home/trustvault/TrustVault')
if str(project_home) not in sys.path:
    sys.path.insert(0, str(project_home))

# Load production .env configuration
env_path = project_home / '.env'
load_dotenv(dotenv_path=env_path)

# Ensure settings module points to config.settings
os.environ.setdefault('SECRET_KEY', '1*(dd4!-4m0-3$ksswf!iz5hn0_^o*lgd+uah@)!t(!$$gd6-)')
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'

# Initialize Django WSGI application
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

Click **Save** at the top right.

---

### Step 7: Reload & Verify Live Deployment

1. Return to the **Web** tab.
2. Click the green button **"Reload trustvault.pythonanywhere.com"**.
3. Open a browser and visit your live domain:
   ```text
   https://trustvault.pythonanywhere.com
   ```
4. Verify health endpoint:
   ```bash
   curl https://trustvault.pythonanywhere.com/health/
   # Response: {"status": "healthy", "service": "TrustVault", "version": "1.0.0"}
   ```
5. Log in with the pre-seeded credentials:
   - **Administrator:** `admin` / `AdminPass123!@#`
   - **Document Owner:** `alice_owner` / `OwnerPass123!@#`
   - **Viewer:** `charlie_viewer` / `ViewerPass123!@#`

---

### Step 8: SQLite Backup Strategy on PythonAnywhere

Because SQLite encapsulates the entire vault database in a single file (`db.sqlite3`), backups are fast and atomic:

```bash
# Manual SQLite snapshot:
mkdir -p ~/backups
cp ~/TrustVault/db.sqlite3 ~/backups/trustvault_backup_$(date +%Y%m%d_%H%M%S).sqlite3

# Backup private documents storage:
tar -czf ~/backups/private_media_$(date +%Y%m%d_%H%M%S).tar.gz -C ~/TrustVault private_media
```

You can automate this by adding a daily scheduled task in the PythonAnywhere **Tasks** tab running:
```bash
cp /home/trustvault/TrustVault/db.sqlite3 /home/trustvault/backups/db_daily.sqlite3
```

---

## 3. Alternative Containerized Deployment (Docker Compose with SQLite3)

For running TrustVault in a containerized environment:

```bash
# Build and launch TrustVault container
docker compose up -d --build

# Run migrations and collect static files
docker compose exec web python manage.py migrate
docker compose exec web python manage.py seed_data
docker compose exec web python manage.py collectstatic --noinput
```
