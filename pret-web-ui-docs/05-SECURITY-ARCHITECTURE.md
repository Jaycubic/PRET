# Phase 5 — LAN-Only Security Architecture

This is the most important document in the set. Every control below must be
enforced **server-side**; the dashboard mockup's "LAN Mode" badge and "Safe
Mode" indicator are UI reflections of these server-side facts, never the
mechanism itself.

## 1. Authorized scope is explicit configuration, not an RFC1918 guess

- The operator configures one or more **explicitly authorized CIDR
  ranges** (e.g. `192.168.1.0/24`) at deployment time, stored server-side
  (config file or DB-backed setting, admin-editable, audit-logged on
  change) — not inferred from "looks private."
- Every outbound connection target (printer IP, IPP/HTTP(S) URL host,
  SNMP target) is checked against this explicit allow-list immediately
  before the connection is opened, in the same code path that opens it —
  not only at "add printer" time, since a device's address can change
  between when it was added and when a job runs.
- Do **not** rely solely on `ipaddress.ip_address(x).is_private` — private-
  range membership is necessary but not sufficient (it doesn't stop an
  attacker-controlled device on the authorized LAN itself from being
  targeted outside the intended scope, and it says nothing about routed
  address space that happens to be private but out of scope). The
  explicit CIDR allow-list is authoritative; "is this address private" is
  only a secondary sanity check, not the control.

## 2. IPv4/IPv6 handling

- Parse and validate using Python's `ipaddress` module for both families.
- IPv6 link-local addresses (`fe80::/10`) require a scope/zone ID to be
  meaningful (`fe80::1%eth0`) — the validator must either require and
  preserve the zone ID or explicitly reject scope-less link-local targets,
  rather than silently connecting to an ambiguous address.
- The authorized-subnet configuration must support IPv6 CIDRs explicitly
  (do not assume the deployment is IPv4-only); an IPv6-capable LAN without
  an IPv6 entry in the allow-list should fail closed, not pass by accident.

## 3. DNS resolution, rebinding, and TOCTOU protection

- If hostnames are accepted at all (vs. requiring raw IPs), resolve the
  hostname **once**, validate the resolved address against the authorized
  CIDR list, then connect to **that resolved address directly** (not the
  hostname again) — this closes the classic DNS-rebinding window between
  validation and connection.
- Re-validate on every job run, not only when a printer is first added:
  a hostname's resolution or a device's address can change over time, and
  the "add printer" record should not be treated as a standing permission
  slip that bypasses re-validation.
- For HTTP(S)/IPP(S) requests, follow the same resolve-then-pin-then-
  connect pattern for every redirect hop (see below) — do not resolve the
  original host, then let an HTTP client library re-resolve and follow a
  redirect to an arbitrary new host on its own.

## 4. Redirect validation and SSRF protection (HTTP/HTTPS/IPP/IPPS)

- Disable automatic redirect-following in the HTTP client, or if followed,
  intercept each redirect response and re-run the full target-validation
  check (CIDR allow-list, resolve-and-pin) against the new location before
  following it. A printer's own admin page redirecting to
  `https://169.254.169.254/` or to a public host must be rejected, not
  silently followed.
- Restrict allowed destination ports to an explicit, small set driven by
  the protocol being used (9100, 515, 631, 161/162, 80, 443, plus any
  admin-configured custom port for a specific device) — never an
  unrestricted port requested by whatever the adapter happens to be given.
- Restrict allowed URL schemes to `http`/`https` only for web-facing
  adapters; never allow `file://`, `ftp://`, `gopher://`, or similar to
  reach the request layer.
- **Fix the existing relaxed-TLS-verification pattern found in Phase 1**
  (`capabilities.py` disables `InsecureRequestWarning` globally for all
  HTTPS probing). The new backend should verify certificates by default
  and only allow a per-target, explicit, audited "trust this self-signed
  cert for this LAN device" exception — never a blanket
  `verify=False` applied to every HTTPS probe regardless of target.

## 5. Timeouts, concurrency, and cancellation

- Every connection (socket, HTTP, SNMP) has an explicit connect + overall
  timeout; PRET's own `conn` has a configurable socket timeout
  (`printer.py` default `self.timeout = 10`) but no concept of an overall
  job timeout — the **job runner**, not PRET, is responsible for killing a
  subprocess that overruns its allotted wall-clock budget.
- A bounded worker pool caps concurrent active jobs (both to protect the
  backend host and to avoid hammering printers, which are frequently
  low-powered embedded devices that degrade under concurrent load).
- Every job is cancellable from the UI/API; cancellation terminates the
  underlying subprocess (and its process tree on Windows/Linux per
  `04-DEPLOYMENT-PORTABILITY.md`), not just marks a DB row as cancelled
  while the process keeps running.
- Per-user/API rate limits on job creation, to prevent accidental or
  malicious scan storms against the LAN's own printers.

## 6. Authentication, authorization, and CSRF

- The web UI requires authentication for all operations; there is no
  anonymous or "LAN access implies trust" bypass, since a compromised LAN
  host (not the operator) could otherwise reach the UI.
- Role separation at minimum: an **operator** role that can run read-only
  discovery/inventory, and an **admin** role required to (a) add/edit
  authorized subnets, (b) run state-changing operations (filesystem
  writes, `fuzz write`, etc.), (c) manage users.
- If cookie-based sessions are used, standard CSRF protection (double-
  submit token or framework-native CSRF middleware) is mandatory, since
  job-creation and configuration-change endpoints are exactly the kind of
  state-changing action CSRF targets.
- Session tokens/cookies: `HttpOnly`, `Secure` (if served over TLS, which
  it should be even on a LAN), `SameSite=Lax` or stricter.

## 7. Credentials and secrets

- SNMP community strings / SNMPv3 auth-priv credentials, and any HTTP
  basic-auth credentials for printer admin pages, are stored encrypted at
  rest (e.g. via the application's own secret key, or integration with the
  host OS's secret store) — never in plaintext config or committed to the
  job/result records.
- Credentials are read into memory only for the duration of the specific
  connection attempt that needs them and are not retained in the in-memory
  job state or written to job logs/result records afterward (see
  `07-DATA-MODEL-AND-MEMORY.md` for the memory-lifecycle detail).

## 8. Audit logging

- Every assessment action (who, what target, what operation, when,
  success/failure, and whether it was read-only or state-changing) is
  written to an append-only audit log table, distinct from the per-job
  technical output log — this is what the dashboard's "Logs" section and
  "Recent Logs" panel are backed by.
- Audit log entries are never deletable through the normal UI (only
  through an explicit, separately-permissioned retention/purge job, if
  retention policy requires one).

## 9. Isolation of risky operations

- Every operation is tagged **read-only / inventory** or **state-changing
  / destructive-capable** in the adapter catalog (`06-PROTOCOL-ADAPTER-
  DESIGN.md`). The UI and API enforce this split structurally: discovery
  and routine inventory jobs can be launched with a single click (as the
  dashboard mockup's "Scan" button suggests); anything state-changing
  (filesystem write/delete fuzzing, PostScript operations that write
  files, the disabled `print`/`edit` commands) requires a separate,
  explicit confirmation step naming exactly what will happen, and is
  blocked entirely unless "Safe Mode" (per the mockup's own header toggle)
  is turned off for that specific job.
- The `print` and `edit` PRET commands are not exposed at all in v1 (see
  `02-INTEGRATION-STRATEGY.md`) rather than exposed-but-gated, since they
  carry disproportionate risk (known CVE-class file-conversion risk,
  meaningless interactive-editor semantics) for limited assessment value.

## 10. No general-purpose shell or arbitrary network request endpoint

- There is **no** API endpoint that accepts a raw shell command, a raw
  PRET command-line string, or an arbitrary URL/host/port triple with no
  catalog/validation behind it. Every operation the browser can request
  maps to one entry in the fixed adapter operation catalog
  (`06-PROTOCOL-ADAPTER-DESIGN.md`), with strictly typed, validated
  parameters (e.g. "target ID" + "which named check," not "command
  string").
- Command-injection and argument-injection are structurally prevented by
  never building a shell string from user input (matching PRET's own
  existing practice of list-form `subprocess` calls with no
  `shell=True`) and by generating PRET command files from the fixed
  operation catalog rather than from free text, as described in
  `02-INTEGRATION-STRATEGY.md`.
- Temporary file handling for job command files and any files fetched
  from a device inherits PRET's `tempfile` usage pattern but closes its
  one gap: `printer.py`'s `NamedTemporaryFile(delete=False)` leaves
  cleanup to the caller — the new job runner explicitly deletes every job
  temp file/directory on job completion or cancellation, scoped to a
  per-job directory so concurrent jobs can't collide or read each other's
  temp files.

## 11. Features disabled by default until further hardened

| Feature | Status | Why |
|---|---|---|
| `print` (ImageMagick/Ghostscript conversion) | Disabled, not exposed | Known CVE-class file-conversion risk per PRET's own code comment; no assessment-value justification |
| `edit` | Disabled, not exposed | Interactive-editor semantics meaningless in a web context |
| Deep filesystem fuzzing (`fuzz write`/`fuzz blind`) | Available, but requires explicit confirmation + Safe-Mode-off, separate from default inventory | State-changing / high find-rate noise; must be a deliberate choice, not a default scan step |
| HTTP(S) admin fingerprinting beyond banner/title | Deferred until specific, vetted per-vendor checks exist | Broadest SSRF-relevant surface; expand deliberately per `03-PROTOCOL-EXPANSION.md` |
| SNMPv3 | Deferred until v1/v2c path is solid | Credential handling adds real complexity; sequence per `03-PROTOCOL-EXPANSION.md` |
