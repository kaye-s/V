# AutoPen — Code security scanning & vulnerability-style reporting

AutoPen is a Django web application where authenticated users upload or paste source code. The backend runs **Semgrep** and **Gitleaks** for static analysis / secret detection, then calls **OpenAI** to produce structured security-incident JSON that powers HTML reports, department queues, and CWE reference browsing. A floating **AI assistant** chat uses the model you choose in Settings.

---

## Tech stack

| Area | Details |
| --- | --- |
| Backend | Python, Django 4.2+, Django REST framework |
| Database | PostgreSQL (`sslmode=require`) |
| Frontend | Server-rendered HTML, CSS, and JavaScript (`front-end/`) |
| Scanning | Semgrep (`--config auto`), Gitleaks (optional; errors are recorded and the pipeline continues per implementation) |
| AI | OpenAI Chat Completions API (report generation + assistant) |

---

## Project layout

| Path | Purpose |
| --- | --- |
| `config/` | Django project settings and root URL config |
| `api/` | Models, views, scanning and AI services (`services/`, `utils/`) |
| `front-end/` | Templates and static assets (`styles/`, `scripts/`, `includes/`) |
| `test_cases/` | Sample code for manual testing |
| `manage.py` | Django management entry point |
| `.env.example` | Template for local secrets (copy to `.env`; safe to commit) |

---

## Features

Unless noted, features require a logged-in user with an **Active** account.

### Accounts & roles

- **Register (`/register/`)**  
  - Collects name, email, password, and department (Frontend / Backend / Database / Cybersecurity).  
  - **Member**: account starts **Pending** until a **manager in the same department** approves it under **Department Approvals**, then becomes **Active**.  
  - **Manager**: if the registration form’s manager code matches the server’s **`MANAGER_SETUP_CODE`**, the account is created as a manager, **Active** immediately, and the user is logged in (see “Environment variables”).

- **Login / logout (`/login/`, `/logout/`)**  
  Sessions use the database plus browser cookies; **restarting `runserver` alone does not log you out**. Use **Logout** or clear site data for localhost to see the login page again.

### Dashboard & scanning

- **Dashboard (`/`)** — Department-level stats, recent submissions, urgent counts, and **Quick Scan** (file upload or pasted code).  
- **Quick scan (`POST /submit/`)** — Same flow as the dashboard form; optional report title; file or paste.  
- **Advanced scan (`/scan/`)** — Upload/paste plus optional **focus line range** and report title.  
- **Pipeline** — Write code to a temp file → Semgrep / Gitleaks → build prompt → OpenAI JSON → persist **Submission** (status, summaries, `report_data`) → redirect to that report.

### Reports & collaboration

- **Reports (`/reports/`)** — Lists **your own** submissions; rename report title (owner only), change **priority** (when allowed), add **comments**.  
- **Report detail (`/report/<submission_id>/`)** — HTML incident-style page for any submission whose owner is in **your department**.  
- **Targets (`/targets/`)** — All submissions in **your department**, ordered by priority and time; comments and priority updates (**owner or same-department manager**).

### Settings & profile

- **Settings (`/settings/`)** — UI theme (Dark / Purple / Blue); AI model slider (speed vs precision axis; options from `OPENAI_MODEL_CHOICES`).  
- **Personal (`/personal/`)** — Display name, password change, cumulative OpenAI token usage.

### AI assistant

Most authenticated pages load the floating assistant; it POSTs to `/assistant/chat/` using the model stored in your settings.

### CWE browser

- **Vulnerabilities (`/vulnerabilities/`)** — Search/filter CWE reference data. This view is **not login-enforced** in code today; add the same guard as other views if you need it internal-only.

### Managers only

- **Department Approvals (`/approvals/`)** — **Managers only** (sidebar link also manager-only). Pending join requests for **your department**: **approve** (user becomes Active and is assigned to that department) or **reject** (account Rejected).

### REST API

- **`/submission/<id>/`** (`SubmissionStatusView`, etc.) — Programmatic submission status (session auth and department rules apply; see `api/views.py`).

### Django Admin

- **`/admin/`** — Requires a superuser (below). Separate from app roles **member** / **manager**.

---

## Member vs manager permissions

Roles are stored as `User.role`: `member` or `manager`. Most reporting is scoped by **`department`**.

| Capability | Member | Manager |
| --- | --- | --- |
| Default state after register | Usually **Pending** until approved | **Active** immediately when registered with correct `MANAGER_SETUP_CODE` |
| Use dashboard, scans, settings, personal | Yes (when Active) | Yes |
| Sidebar “Department Approvals” | No | Yes |
| Approve/reject join requests for the department | No | Yes |
| **Reports** page scope | **Own** submissions only | **Own** submissions only (same queryset as members) |
| **Targets** page scope | Entire **department** | Entire **department** |
| Change **priority** on **Reports** | **Own** submissions only | **Own** submissions only; use **Targets** for teammates |
| Change **priority** on **Targets** | **Own** submissions only | **Own** or **other users in the same department** |
| Open `/report/<id>/` | Yes if submitter is **same department** | Same |
| Comments on Reports / Targets | Where the UI allows | Same |

**Summary:** Managers mainly differ by **onboarding approvals** and by adjusting **priority for teammates** on **Targets**.

---

## Environment variables (`.env`)

Configuration is loaded with **`python-decouple`** from a **`.env` file in the project root** (the same directory as `manage.py`). That file is listed in **`.gitignore`** and must **not** be committed.

### Setup

1. Copy the template and edit locally:

   ```bash
   cp .env.example .env
   ```

2. Open `.env` in an editor and set **your own** values for every key below.  
   **Do not put real secrets in `README.md`, screenshots, or git history.** If you use hosted PostgreSQL (e.g. Supabase), use the host, port, user, and password from their dashboard—often the pooler uses port **`6543`** instead of `5432`; match whatever your provider documents.

### Required keys

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Django [`SECRET_KEY`](https://docs.djangoproject.com/en/stable/ref/settings/#secret-key); long random string unique to your deployment |
| `DB_HOST` | PostgreSQL hostname |
| `DB_PORT` | PostgreSQL port (often `5432`; poolers may use e.g. `6543`) |
| `DB_NAME` | Database name |
| `DB_USER` | Database user |
| `DB_PASS` | Database password |
| `OPENAI_API_KEY` | OpenAI API key (`sk-…`) |
| `OPENAI_REPORT_MODEL` | Default model ID when none is selected (e.g. `gpt-5.4`) |
| `OPENAI_MODEL_CHOICES` | Comma-separated list for the Settings slider (e.g. `gpt-5.5,gpt-5.4,gpt-5.4-mini`) |
| `MANAGER_SETUP_CODE` | Secret string; registering with this code in the manager field creates an **Active** **manager** account |

### Example shape (placeholders only — use `.env.example` in the repo)

```env
SECRET_KEY=your-generated-secret-not-this-text
DB_HOST=your-db-host.example.com
DB_PORT=5432
DB_NAME=postgres
DB_USER=your_db_user
DB_PASS=your_db_password
OPENAI_API_KEY=sk-your-key-here
OPENAI_REPORT_MODEL=gpt-5.4
OPENAI_MODEL_CHOICES=gpt-5.5,gpt-5.4,gpt-5.4-mini
MANAGER_SETUP_CODE=your-private-manager-bootstrap-string
```

---

## System dependencies (scanners)

- **Semgrep** — Install so `python -m semgrep` works, or follow [Semgrep docs](https://semgrep.dev/docs/getting-started).  
- **Gitleaks** — If `gitleaks` is on `PATH`, the scan runs; otherwise errors are recorded and the rest of the flow may still continue.

---

## How to run — Option A: Web browser (recommended)

### 1. Virtual environment and Python deps

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure `.env`

Copy `.env.example` to `.env`, fill in PostgreSQL and OpenAI values (see **Environment variables** above), then ensure the database is reachable from your machine (`sslmode=require` is set in `config/settings.py`).

### 3. Migrate and start the dev server

```bash
python manage.py migrate
python manage.py runserver
```

### 4. Open in a browser

Default URL: `http://127.0.0.1:8000/`

- Register first. To create a **manager**, enter the same value as `MANAGER_SETUP_CODE` in the manager code field.  
- Ordinary members stay **Pending** until a **department manager** approves them at **`/approvals/`**.

### 5. (Optional) Django Admin

```bash
python manage.py createsuperuser
```

Then visit `/admin/`.

---

## How to run — Option B: Electron desktop shell (optional)

This repository **does not** ship root-level `package.json` / `main.js`. Electron simply opens a window pointing at the **same URL** as the browser; you still start Django as in **Option A**.

### Prerequisites

- **Node.js** and **npm**.  
- Django running (e.g. `python manage.py runserver`).  
- Use one host consistently (`http://127.0.0.1:8000` vs `http://localhost:8000`) so cookies and sessions stay aligned.

### Local setup

From the project root (or another folder you prefer):

```bash
npm init -y
npm install --save-dev electron
```

Add `main.js` next to `package.json`:

```javascript
const { app, BrowserWindow } = require("electron");

function createWindow() {
  const win = new BrowserWindow({ width: 1200, height: 800 });
  win.loadURL("http://127.0.0.1:8000");
}

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
```

In `package.json`, set `"main": "main.js"` and add:

```json
"scripts": {
  "start": "electron ."
}
```

Start Django, then:

```bash
npm start
```

Do not commit `node_modules/`. Whether to commit local `package.json` / `package-lock.json` / `main.js` is up to your team policy.

---

## Route reference

| Path | Description |
| --- | --- |
| `/` | Dashboard (auth required) |
| `/login/`, `/logout/` | Sign in, sign out |
| `/register/` | Registration |
| `/submit/` | POST target for Quick Scan |
| `/scan/` | Advanced scan form |
| `/reports/` | Your reports and actions |
| `/targets/` | Department queue |
| `/report/<submission_id>/` | Single report (department scope) |
| `/settings/` | Theme & AI model |
| `/personal/` | Profile, password, usage |
| `/vulnerabilities/` | CWE list (not login-enforced in code) |
| `/approvals/` | Department onboarding (**managers only**) |
| `/assistant/chat/` | Assistant API (POST, auth required) |
| `/submission/<id>/` | REST submission status |
| `/admin/` | Django admin |

---

## Limits & notes

- Single-file uploads are capped at **2 MiB** (`MAX_UPLOAD_BYTES`).  
- Report generation truncates code sent to the model (e.g. first ~8000 characters) and caps Semgrep/Gitleaks finding counts for token control.  
- Sessions persist in the DB and browser; restarting only the dev server usually leaves you signed in if the cookie is still present.
