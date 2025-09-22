# NIMBUS
Nimbus is an intelligent browser extension and a powerful backend system designed to simplify cloud storage management. It allows users to connect various cloud services like Google Drive, Dropbox, and OneDrive, providing a unified platform to optimize storage space and ensure secure, instant access to files across all linked accounts.

## Project layout
- Backend: FastAPI app in `backend/`
- Frontend: Static HTML pages in project root (`login.html`, `dashboard.html`, `connections.html`)

## Prerequisites
- Python 3.11 or 3.10 recommended (Python 3.13 may require Rust toolchain to build pydantic-core)
- PostgreSQL reachable at the host/port you configure in `backend/.env` (defaults to localhost:5433)

If you must stay on Python 3.13, install Rust (cargo) or upgrade pydantic to a version that ships wheels for your Python version.

## Backend setup
1. Create and use a virtual environment (example using `venv`):
   - Windows PowerShell:
     - python -m venv .venv
     - .\.venv\Scripts\Activate.ps1
2. Install dependencies:
   - pip install --upgrade pip setuptools wheel
   - pip install -r requirements.txt
3. Configure environment:
   - Copy `backend/.env` and adjust values as needed (DB, OAuth, FRONTEND_URL, etc.)
   - Ensure `FRONTEND_URL` is the origin you use to serve the static files, e.g. `http://localhost:3000`
4. Initialize DB (optional in dev):
   - python backend/database.py
5. Run the API server:
   - uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

## Frontend (static) setup
Serve static files so the origin matches CORS allowed origins in the backend. One easy way:
- python -m http.server 3000

Then open:
- http://localhost:3000/login.html

The login page will POST to the backend at `http://localhost:8000/auth/login` and on success will save the token and redirect to the dashboard.

## Environment variables
Backend reads from `backend/.env`. Keys present:
- DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DATABASE_URL
- SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, FERNET_KEY
- GOOGLE_CLIENT_ID, GOOGLE_REDIRECT_URI
- DROPBOX_CLIENT_ID, DROPBOX_CLIENT_SECRET, DROPBOX_REDIRECT_URI
- FRONTEND_URL, EXTENSION_ID, HOST, PORT, ENVIRONMENT

Do not commit real secrets.
