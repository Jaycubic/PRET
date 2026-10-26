# Frontend Implementation Plan

This is the missing piece: how the browser side gets built, matching the
dashboard screenshot you shared, and wired to the backend/API contract
already defined in `02-INTEGRATION-STRATEGY.md` and
`06-PROTOCOL-ADAPTER-DESIGN.md`.

## Design intent: pure abstraction over the operation catalog

The whole point of the adapter/catalog design in `06-PROTOCOL-ADAPTER-
DESIGN.md` is that the frontend never needs protocol-specific knowledge.
Concretely:

- "Add Printer" is one form: IP/hostname, optional port, optional protocol
  hint. It posts to `POST /api/devices`. The frontend doesn't know or care
  that PJL/PCL/PS exist as separate PRET modes underneath — that's the
  backend's job via `02-INTEGRATION-STRATEGY.md`'s subprocess path.
- The operation buttons shown per device ("Run PJL Commands", "Check for
  Vulnerabilities", "Get Device Info", "Enumerate Filesystem" in your
  mockup) are **rendered from `GET /api/adapters`**, not hardcoded — each
  button is just `{adapter_id, operation_id, display_name, read_only}`
  from the catalog. Adding a new protocol adapter on the backend makes new
  buttons appear automatically; no frontend code change, exactly as
  `06-PROTOCOL-ADAPTER-DESIGN.md` requires.
- State-changing operations (`read_only: false`) render with the orange/
  red treatment your mockup already uses for destructive-looking actions,
  and open a confirmation modal before the job is submitted — this is the
  UI half of the server-side confirmation-token requirement in
  `05-SECURITY-ARCHITECTURE.md` §9.

## Tech stack recommendation

**Plain HTML/CSS/JS (no build step) for v1**, not React/Vue, because:

- The whole app is server-rendered-data + REST + WebSocket — there's no
  complex client-side routing or component-tree depth that justifies a
  framework yet.
- No build pipeline means the static files can be served directly by the
  same backend process (FastAPI's `StaticFiles` mount), which keeps
  deployment to exactly one process on Linux/Windows, consistent with
  `04-DEPLOYMENT-PORTABILITY.md`'s "smallest architecture" principle.
- If the UI grows real complexity later (many simultaneous live job views,
  heavy client state), migrating specific pages to React is a contained,
  later decision — not a day-one requirement.

## Page / view inventory (matches your sidebar exactly)

| Sidebar item | Route | Backed by |
|---|---|---|
| Dashboard | `/` | `GET /api/devices` (summary), `GET /api/jobs?status=running` (stat tiles), `GET /api/audit_log?limit=5` (Recent Logs) |
| Add Printer | inline panel on Dashboard, not a separate route | `POST /api/devices` |
| Discovered Printers | `/devices` | `GET /api/devices`, plus a "Discover now" action hitting `POST /api/jobs` with the mDNS/SNMP discovery adapter |
| Scan / Enumerate | per-device, not global | `POST /api/jobs` with a read-only catalog operation |
| Exploitation Modules | per-device tab | `GET /api/adapters` filtered to `read_only: false` for that device's detected protocols |
| Logs | `/logs` | `GET /api/audit_log` (paginated) |
| Settings | `/settings` | `GET/PUT /api/settings` — this is where the authorized-subnet allow-list from `05-SECURITY-ARCHITECTURE.md` §1 and the network-route/pivot config from `10-NETWORK-TUNNEL-ARCHITECTURE.md` are managed, admin-role only |

Per-device detail view (`/devices/{id}`) has the five tabs from your
mockup — Overview, Enumeration, Exploitation Modules, Raw Commands, Logs —
each a thin view over `GET /api/devices/{id}`, `GET /api/devices/{id}/
results`, `GET /api/adapters`, and `GET /api/devices/{id}/jobs`
respectively. "Raw Commands" is **not** a free-text field (per
`05-SECURITY-ARCHITECTURE.md` §10) — it's a read-only transcript viewer for
a completed job's captured PRET session output, not an input.

## State and live updates

- Initial page load: plain `fetch()` calls populate state.
- Live job progress and the "Recent Logs" tail: one WebSocket connection
  (`/ws/jobs`) the dashboard opens on load; incoming messages are
  `{job_id, status, log_line}` events that patch the relevant job row and
  append to the log panel in place — no polling loop needed once the
  socket is open, falling back to short-interval polling only if the
  socket connection fails (keeps the UI usable even if WebSocket is
  blocked by an intermediate proxy).
- No client-side state library needed yet — a small per-page module-level
  state object plus direct DOM updates is enough at this scale; revisit
  only if/when the React migration mentioned above actually happens.

## Confirmation flow for state-changing operations

Matches `05-SECURITY-ARCHITECTURE.md` §9 exactly:

1. User clicks a `read_only: false` operation button.
2. Modal shows: exact operation name, exact target, plain-language
   description of what it does, and requires typing the device's IP (or a
   checkbox + explicit "Confirm" button) to proceed — no bare "OK".
3. On confirm, frontend calls `POST /api/jobs` with
   `{..., confirm: true}`; backend issues the `confirmation_token` and
   proceeds. Without `confirm: true`, the backend must reject state-
   changing job creation outright — the frontend confirmation is UX, the
   backend check is the actual control.
4. "Safe Mode" (the header toggle in your mockup) is a **per-session UI
   preference that maps to a real backend enforcement flag**, not a purely
   cosmetic switch — when on, the frontend hides/disables state-changing
   operation buttons entirely, and the backend independently refuses
   `read_only: false` job creation for that session regardless of what the
   client sends, so a tampered client can't re-enable it.

## Build/deploy

- `frontend/` is plain static assets (`index.html`, `app.js`, `styles.css`,
  maybe split per-page later) served by the backend at `/`, with `/api/*`
  and `/ws/*` handled by the same FastAPI process — one deployable unit,
  one systemd service, matching `04-DEPLOYMENT-PORTABILITY.md`.
- No Node/npm toolchain required for v1, which also keeps the Windows
  portability story simple (no second language runtime to install).

## What's attached alongside this doc

`prototype-dashboard.html` is a working, self-contained implementation of
the Dashboard + Add Printer + device detail view from your screenshot,
running against in-memory mock data so you can click through the actual
interaction model (add an IP, see it appear, click into it, see tabs, see
a confirmation modal on a destructive-looking action) before the backend
API exists. Every place it currently uses mock data is marked with a
`// TODO: replace with fetch(...)` comment pointing at the real endpoint
from the table above, so swapping in the real backend is a mechanical
pass, not a rewrite.
