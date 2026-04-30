# Code security scanning and vulnerability reports

A Django app for user sign-up, sign-in, and a code upload and analysis flow. The pipeline runs **Semgrep** and **Gitleaks** as a pre-scan, then uses **OpenAI** to generate risk summaries and security-incident style reports, plus vulnerability lists and per-submission report pages.

## Tech stack

| Area | Details |
| --- | --- |
| Backend | Python, Django 4.2+, Django REST framework |
| Database | PostgreSQL (`sslmode=require`) |
| Frontend | Static HTML, CSS, and JavaScript (`front-end/`) |
| Scanning | Semgrep (`--config auto`), Gitleaks (optional; if missing, the step surfaces an error and continues per implementation) |
| AI | OpenAI API (e.g. `gpt-4.1-mini`—see code) |

## Project layout (overview)

- `config/` – Django project settings and URL config
- `api/` – Models, views, serializers, scanning and AI services (`services/`, `utils/`)
- `front-end/` – Pages and static assets (`styles/`, `scripts/`)
- `test_cases/` – Sample code for testing
- `manage.py` – Django management entry point

## Environment variables

Create a `.env` in the project root (or use your `python-decouple` loading pattern). You need at least:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Django secret key |
| `DB_NAME` | PostgreSQL database name |
| `DB_USER` | Database user |
| `DB_PASS` | Database password |
| `DB_HOST` | Hostname |
| `DB_PORT` | Port (optional, default `5432`) |
| `OPENAI_API_KEY` | OpenAI API key for analysis and report content |

## System dependencies (scanners)

- **Semgrep** – Install via `pip install semgrep` or the [official method](https://semgrep.dev/docs/getting-started) so `python -m semgrep` works.
- **Gitleaks** – If the `gitleaks` binary is on your `PATH`, pre-scan runs it; if not, that step returns a message and the rest of the flow may still continue.

## Install and run

1. **Create a virtual environment** (recommended) and install dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Database** – Ensure PostgreSQL is reachable and `.env` matches your instance.

3. **Migrate and start the dev server:**

   ```bash
   python manage.py migrate
   python manage.py runserver
   ```

4. Open `http://127.0.0.1:8000/` in a browser. You must **register and sign in** before using the dashboard and upload scan.

## Main routes (reference)

| Path | Description |
| --- | --- |
| `/` | Dashboard (auth required) |
| `/login/`, `/logout/` | Sign in, sign out |
| `/register/` | Registration |
| `/submit/` | Submit code for scanning |
| `/submission/<id>/` | Submission status / results (API view) |
| `/vulnerabilities/` | Vulnerability list |
| `/report/<submission_id>/` | Report for one submission |
| `/admin/` | Django admin |

Single-file uploads are limited to **2 MiB** (see `MAX_UPLOAD_BYTES` in the app); larger files are rejected.

## Admin

Create a superuser to use `/admin/`:

```bash
python manage.py createsuperuser
```
