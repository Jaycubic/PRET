# PRET Web UI

A browser-based printer security assessment platform built around
[PRET](https://github.com/RUB-NDS/PRET) (Printer Exploitation Toolkit).
Built for **authorized** penetration testing, cyber-learning labs, and
defensive security research on printer networks. Read `DISCLAIMER.md`
before using this against anything.

> **Status: Feature-Complete Platform.** All 10 protocol & discovery adapters
> (PJL, PCL, PostScript, SNMPv1/v2c, SNMPv3, mDNS, IPP/IPPS, CUPS print-server auditing,
> HTTP/HTTPS admin fingerprinting with redirect re-validation, and WSD / WS-Discovery)
> are fully implemented and verified. Includes full multi-view UI, automated test suite,
> Docker containerization, systemd unit, and Windows service automation. See
> `pret-web-ui-docs/12-MASTER-BUILD-PLAN.md` for full implementation history.

## What this is

- A modern browser-based security assessment platform wrapping PRET's PJL/PCL/PostScript
  engines and modern network protocols (SNMPv2c/v3, IPP/IPPS, mDNS, WSD, CUPS server audits,
  HTTP admin fingerprinting) for devices on **explicitly authorized subnets**.
- Strict server-enforced LAN/subnet scoping — every target, discovery result, and redirect hop
  is re-validated server-side against an administrator-managed CIDR allow-list.
- Multi-protocol automated discovery: one-click mDNS (Bonjour) and WS-Discovery (WSD) sweeps.
- An SSH-tunnel ("pivot") layer allowing authorized assessors to reach isolated printer segments
  through dual-homed pivot hosts without altering PRET code.
- Comprehensive automated test suite (`tests/`) running without touching live printers.

## Architecture at a glance

Full design docs are in `pret-web-ui-docs/` — start with
`00-AGENT-INSTRUCTIONS.md` for the reading order, or
`12-MASTER-BUILD-PLAN.md` for current status and what's next.

```
frontend/   TypeScript + React + Vite — built into backend/app/static/
backend/    FastAPI + SQLAlchemy — the API, job runner, adapters, auth
pret/       Vendored, UNMODIFIED upstream PRET (GPLv2) — see
            THIRD_PARTY_LICENSES.md
pret-web-ui-docs/   The full design/architecture/security documentation set
```

## Requirements

- Python 3.11+
- Node.js 18+ (only needed to build the frontend; not required at runtime)
- Linux (primary target) or Windows (supported, some features — like
  local/USB printer targets — are Linux-only; see
  `pret-web-ui-docs/04-DEPLOYMENT-PORTABILITY.md`)

## Setup

### 1. Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then edit SECRET_KEY at minimum
```

Generate a real secret key rather than using the placeholder:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Paste that into `.env` as `SECRET_KEY=`.

### 2. Frontend (build once; the backend serves the built output)

```bash
cd frontend
npm install
npm run build
```

This outputs into `backend/app/static/`, which the backend serves
directly — no separate frontend server needed in production.

### 3. Run

```bash
cd backend
PRETWEB_ADMIN_PASSWORD=choose-a-real-password \
  venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8443
```

Open `http://0.0.0.0:8443`. Log in as `admin` with the password you set
above.

**If you don't set `PRETWEB_ADMIN_PASSWORD`**, the app creates
`admin` / `change-me-now` and prints a loud warning — change it
immediately via the database or by deleting `backend/data/pretweb.db`
and restarting with the env var set.

### 4. First-run checklist (do this before scanning anything)

1. Log in.
2. Go to **Settings → Authorized Networks** and add the CIDR(s) you are
   explicitly authorized to assess (e.g. `192.168.1.0/24`). **Nothing
   outside this list can be scanned, by design** — confirmed by this
   project's own tests: adding a device before any authorized network
   exists is rejected with HTTP 403.
3. (Optional) If you need to reach a segment through a pivot host, add a
   **Network Route** under Settings first — see
   `pret-web-ui-docs/10-NETWORK-TUNNEL-ARCHITECTURE.md`.
4. Add a printer by IP/hostname, now that it's in scope.
5. Safe Mode is on by default — state-changing operations are blocked
   both in the UI and independently on the server until you turn it off
   and explicitly confirm an operation.

### Dev mode (frontend hot-reload)

```bash
# terminal 1
cd backend && venv/bin/uvicorn app.main:app --reload --port 8443
# terminal 2
cd frontend && npm run dev
```

Open the Vite dev server's URL (usually `http://localhost:5173`) — it
proxies `/api` and `/ws` to the backend (see `frontend/vite.config.ts`).

## Running on Windows (PowerShell)

To run the application and track the logs in real time in your own terminal windows:

### Option A: Standard Full-Stack Mode (Single Backend Server)
Since the frontend has been built into `backend/app/static/`, the backend serves the entire UI:

```powershell
cd d:\AcademicPlanning\PRET\backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8443
```
- Open **http://localhost:8443** (or `http://172.16.182.155:8443` from any device on your Wi-Fi).
- All API and device access logs will stream in this PowerShell window.

---

### Option B: Development Mode (Hot-Reloading with 2 Terminals)

**Terminal 1 (Backend API):**
```powershell
cd d:\AcademicPlanning\PRET\backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8443 --reload
```

**Terminal 2 (Frontend Dev Server):**
```powershell
cd d:\AcademicPlanning\PRET\frontend
npm run dev -- --host 0.0.0.0
```
- Open **http://localhost:5173** (or `http://172.16.182.155:5173`).
- Frontend hot-reload and backend request logs stream live in their respective terminal windows.

---

### ⚠️ Important: Authorizing Network Printers (CIDR Scope)
PRET strictly blocks scanning any IP not in your authorized scope (returns `HTTP 403 Forbidden`):
- To authorize your local PC: add `172.16.182.155/32`
- To scan printers on your Wi-Fi subnet (e.g. `172.16.159.*`): add **`172.16.128.0/18`** (or `172.16.159.0/24`) under **Settings → Authorized Networks**.

## Security model (read this)

This is not a general-purpose scanner. Every design decision in
`pret-web-ui-docs/05-SECURITY-ARCHITECTURE.md` is enforced in the actual
code, not just documented:

- The browser never sends a raw command — every operation is a fixed,
  validated entry in an adapter's operation catalog
  (`pret-web-ui-docs/06-PROTOCOL-ADAPTER-DESIGN.md`).
- Target scope is validated server-side on every single job, not just
  when a device is added.
- State-changing operations require explicit, typed confirmation in the
  UI **and** are independently refused by the API without a `confirm`
  flag — a compromised/tampered client can't bypass this.
- Full audit log of every action, who did it, and the outcome.

## License

**GPLv2** — see `LICENSE`. This project vendors unmodified upstream PRET
(also GPLv2) and is licensed to match, including the new backend/frontend
code. See `THIRD_PARTY_LICENSES.md` for why, and what that means if you
redistribute a modified version.

## Contributing / extending

The protocol adapter interface (`backend/app/adapters/base.py`) is
designed so a new protocol is a self-contained adapter module plus a
registry entry — no frontend changes needed, since the UI renders
whatever `/api/adapters` reports. See
`pret-web-ui-docs/06-PROTOCOL-ADAPTER-DESIGN.md` and
`pret-web-ui-docs/12-MASTER-BUILD-PLAN.md` for the planned adapters and
current status.
