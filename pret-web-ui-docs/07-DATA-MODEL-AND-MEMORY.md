# Data Model and Memory Management

This file covers both halves of "persistence": the **database** (durable,
shared, source of truth) and **in-process memory** (transient, per-job,
must be bounded and cleaned up deliberately). PRET itself has neither
concept today (Phase 1 finding: no DB, no job model anywhere in the
upstream repo) — everything here is new.

## 1. Database choice

- **SQLite by default** for a single-host LAN deployment (zero extra
  service to run, trivially backed up as one file, entirely adequate for
  the expected scale: a handful of printers, a small assessment team).
- **PostgreSQL as a supported, documented option** for larger/shared
  deployments (concurrent writers, multiple backend instances) — same
  schema, via SQLAlchemy so the application code doesn't fork per backend.
- Access through an ORM (SQLAlchemy) with Alembic-style migrations from day
  one, even on SQLite — schema changes are inevitable as protocol adapters
  grow, and hand-written migration discipline avoids painful ad hoc
  `ALTER TABLE`s later.

## 2. Schema

```
users
  id, username, password_hash, role (operator|admin), created_at,
  last_login_at, is_active

devices                      -- "Discovered / Added Printers" table
  id, ip_or_hostname, resolved_ip, port, hostname, model, firmware,
  mac_address, location, contact, protocol_hint, status (online|offline|
  unknown), first_seen_at, last_seen_at, added_by_user_id, source
  (manual|snmp_discovery|mdns_discovery)

device_services               -- "Open Services" panel
  id, device_id (FK), port, protocol_name, state (open|closed|filtered),
  detected_at, detection_method (adapter_id)

jobs
  id, device_id (FK, nullable for e.g. network-wide discovery jobs),
  adapter_id, operation_id, status (queued|running|succeeded|failed|
  cancelled|timeout), requested_by_user_id, requested_at, started_at,
  finished_at, is_state_changing (bool), confirmation_token (set only when
  a state-changing job was explicitly confirmed), params_json (validated
  params actually used, for traceability — never raw user text)

results                        -- see common Result model in
  id, job_id (FK), device_id (FK), adapter_id, operation_id, timestamp,
  06-PROTOCOL-ADAPTER-DESIGN.md
  status, severity, summary, evidence_json (size-capped, see §4), 
  remediation, error_detail

audit_log                      -- append-only, never UI-deletable
  id, user_id, action, target_device_id (nullable), job_id (nullable),
  timestamp, source_ip, outcome (success|failure), detail

credentials                    -- SNMP community/v3, HTTP admin creds
  id, device_id (FK), kind (snmp_v2c|snmp_v3|http_basic|...),
  encrypted_blob, created_by_user_id, created_at
  -- never referenced from `results` or `jobs` by value, only by this
  -- table's id, and the blob is decrypted only transiently in memory
  -- during the one connection attempt that needs it (see §5)

settings
  key, value_json, updated_by_user_id, updated_at
  -- includes the authorized-subnet allow-list from
  -- 05-SECURITY-ARCHITECTURE.md §1, itself audit-logged on change via
  -- audit_log whenever it's updated
```

Indexes: `devices.resolved_ip`, `jobs.status`, `jobs.device_id`,
`results.device_id`, `audit_log.timestamp` — chosen for the dashboard's own
query patterns (device list, live job status, recent logs, per-device
history).

## 3. What is deliberately *not* stored

Per security-architecture rule on minimal retention:

- Full raw PRET subprocess stdout/stderr is **not** persisted verbatim by
  default — it's parsed into `results` rows (structured), and only the
  last N KB of raw output is retained transiently for operator debugging
  of a specific failed job (capped, see §4), auto-purged after a
  configurable retention window.
- Full file contents pulled from a device's filesystem (via PJL/PS
  filesystem commands) are not stored in the DB; only metadata (path,
  size, existence) and, if the operator explicitly requests it for a
  specific finding, a capped preview — never a silent full dump into
  `evidence_json`.
- Credentials are stored only in the dedicated encrypted `credentials`
  table, never copied into `jobs.params_json`, `results.evidence_json`, or
  log files.

## 4. Size caps (both DB and memory)

- `evidence_json` per result: hard cap (e.g. 16 KB) with explicit
  truncation markers — a device that returns a huge directory listing or
  PostScript error dump should produce a truncated-but-honest record, not
  an unbounded blob that eventually degrades DB/query performance or lets
  one noisy device exhaust disk space.
- Per-job raw-log retention: capped similarly, with the understanding that
  cap tuning is an operational knob (`settings` table), not a hardcoded
  constant buried in code.

## 5. In-process memory management (the "proper memory management" requirement)

This is about the backend process's own runtime memory, distinct from the
database:

1. **Job state lives in the database, not only in process memory.** The
   in-memory job registry (a dict of `job_id -> handle` for the currently
   running subprocess/task) is a cache of *active* jobs only — the moment
   a job finishes, its handle is removed from memory; its result is
   already durable in the DB. A backend restart loses only "what was
   running," which is recoverable (jobs are re-queryable from the DB and
   marked `failed`/interrupted on restart), not "what happened."
2. **Bounded worker pool**, not unbounded task spawning. A fixed-size pool
   (configurable, defaulting to something small like 4-8 concurrent jobs)
   backed by a queue in the DB (`jobs.status = queued`) — this bounds both
   OS process count (each PJL/PCL/PS job is a real subprocess) and memory
   held by in-flight buffers.
3. **Streaming, not buffering, for subprocess output.** Read the
   subprocess's stdout/logfile incrementally (line-by-line or chunked) and
   push each chunk to (a) the DB-backed capped log store and (b) any
   connected WebSocket/SSE listeners, rather than reading the entire
   output into a Python string/list before processing — this keeps a
   single large or runaway job from spiking process memory, and is also
   what makes the "Recent Logs" live-tailing in the mockup possible at all.
4. **Explicit temp-file and temp-directory lifecycle**, scoped per job
   (`<tmp_root>/jobs/<job_id>/`), deleted on job completion, cancellation,
   or (as a backstop) by a periodic sweep of orphaned job directories
   older than a threshold — directly closing the gap noted in Phase 1
   where PRET's own `tempfile.NamedTemporaryFile(delete=False)` leaves
   cleanup to the caller.
5. **Credentials decrypted only for the connection's duration.** Pull the
   encrypted blob from `credentials`, decrypt into a local variable scoped
   to the adapter call that needs it, and let it go out of scope
   immediately after use — never attach decrypted credentials to a job
   handle or any longer-lived object, and never log them even at debug
   level (the adapter layer should scrub known credential fields before
   anything is written to the capped job log).
6. **Backpressure on log/result ingestion.** If a device/job is producing
   output faster than the DB or websocket consumers can absorb it (a slow
   client tab, a large directory fuzz), the capped-size rule in §4 is the
   backstop — writers should cap and drop with a visible "truncated"
   marker rather than growing an in-memory buffer unboundedly while
   waiting for a slow consumer.
7. **Discovery jobs (SNMP broadcast, mDNS browse) are time-boxed and their
   listener objects explicitly closed** when the discovery window ends —
   `discovery.py`'s own `asyncore` dispatcher and any `zeroconf.Zeroconf()`
   instance must be closed/stopped deterministically (not left running)
   once results are collected, both to free memory and to stop generating
   network traffic after the operator's requested discovery window.

## 6. Why this is proportionate (not over-engineered)

No separate cache layer (Redis, etc.) is introduced for v1: the DB itself
(SQLite/Postgres) serves as both the durable store and the natural
"what's currently true" source for the dashboard's polling/refresh needs,
and the small in-memory active-job registry described above is enough to
route live log chunks to open WebSocket connections without a pub/sub
broker. This can be revisited explicitly in a later phase if multi-instance
horizontal scaling becomes a real requirement — see the open questions in
`09-ROADMAP.md`.
