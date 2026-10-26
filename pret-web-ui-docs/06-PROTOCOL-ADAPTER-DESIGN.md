# Phase 6 — Protocol Adapter Design

## Conceptual interface

Every protocol module (PJL/PCL/PS via PRET subprocess, SNMP, IPP/IPPS, mDNS,
HTTP(S), future LPD) implements the same shape, regardless of how it talks
to the device underneath:

```
Adapter
  .id                      -> stable string, e.g. "pjl", "snmp_v2c", "ipp"
  .display_name            -> human label for the UI
  .platform_support        -> {"linux": True, "windows": True/False, "notes": "..."}
  .dependency_status()     -> checks required libs/binaries are present and
                               usable *right now* (mirrors the real
                               `snmp_modules_found`-style degradation found
                               in PRET's own discovery.py — report it to the
                               UI instead of letting it fail silently)
  .detect(target)           -> is this protocol/service present & reachable?
                                (fast, read-only, short timeout)
  .get_identity(target)     -> device identity/capability summary, if the
                                protocol exposes one (model, firmware, etc.)
  .list_operations()         -> the fixed catalog of operations this adapter
                                exposes, each tagged read_only / state_changing,
                                with a JSON-schema-like parameter spec
  .run_operation(op_id, target, params, progress_cb) -> structured Result(s)
  .cancel(job_handle)        -> best-effort cancellation
```

This is a conceptual contract (duck-typed Python base class / `Protocol`
is fine), not a mandate to use these exact method names — but every
concrete adapter must expose equivalents of all of the above, because the
job runner and UI are both written against this shape, not against any one
protocol's quirks.

## Operation catalog, not free-form commands

Each adapter's `list_operations()` return value is the **entire** surface
the browser can ever trigger for that protocol. For the PJL/PCL/PS adapter
specifically (the one backed by a PRET subprocess), each catalog entry maps
to a **fixed, backend-authored PRET command template** with named,
validated parameters substituted in — e.g.:

```
operation: "pjl_list_variables"
read_only: true
pret_template: "info variables"        # verbatim PRET command, no user input

operation: "pjl_dir_list"
read_only: true
params: { path: <validated device-path string, allow-listed charset,
                  traversal sequences rejected> }
pret_template: "ls {path}"

operation: "fuzz_write_fs"
read_only: false
requires_confirmation: true
pret_template: "fuzz write"
```

The browser never sends a raw command string; it sends `{operation_id,
target_id, params}`, and the backend is the only thing that ever
constructs the actual PRET command file content, after validating
`params` against that operation's declared schema. This is the concrete
mechanism behind the security-architecture rule "no general-purpose shell
or arbitrary command endpoint."

## Registration, versioning, testing

- Adapters register themselves in a small in-process registry (a dict
  keyed by `id`, populated at startup by importing a fixed, explicit list
  of adapter modules — **not** dynamic plugin auto-discovery from an
  arbitrary directory, which would reopen the "arbitrary code" concern
  this whole design is trying to close off).
- Each adapter carries its own semantic version string; the result model
  (below) records which adapter version produced a given finding, so
  historical results remain interpretable after an adapter changes.
- Each adapter ships its own unit tests (parsing, validation) and
  integration tests against a mock/simulated service for that protocol
  (per `08-TESTING-STRATEGY.md`) — a new adapter isn't "done" without
  both.
- The frontend lists available operations **dynamically** from
  `GET /api/adapters` (id, display name, operations, read_only flags,
  parameter schemas) rather than hardcoding a per-protocol UI — this is
  what lets a new adapter be added without frontend changes, as the brief
  requires, and without touching the core job-execution system (which only
  ever deals in `{adapter_id, operation_id, target_id, params}` tuples and
  the common result model).

## Common result model

```
Result
  target_id        -> FK to the printer/device record
  adapter_id        -> e.g. "pjl", "snmp_v2c"
  operation_id      -> e.g. "pjl_list_variables"
  job_id            -> FK to the job that produced it
  timestamp
  status            -> ok | error | timeout | unsupported
  severity          -> info | low | medium | high | critical (for
                       vulnerability/misconfiguration-style findings;
                       null/"info" for plain inventory results)
  summary           -> short human-readable one-line result
  evidence          -> structured, size-capped payload (see memory doc for
                       the cap and why) — not the full raw device output
                       by default
  remediation       -> guidance text, present only for non-"ok" security
                       findings
  error_detail      -> present only when status is error/timeout
```

This single shape is what every protocol's findings get normalized into
before being shown in the "With Vulnerabilities"/"Issues Found" dashboard
tiles and the per-device "Enumeration"/"Exploitation Modules" tabs in the
mockup — the UI renders this one model, never protocol-specific shapes
directly.
