# Phase 2 — Web Integration Strategy

## Decision: controlled subprocess per job, not an imported library, not a rewrite

| Option | Verdict | Why |
|---|---|---|
| Import PRET classes directly in-process | **Rejected** | `printer.__init__` connects and immediately calls `cmdloop()` (blocking stdin REPL); `do_exit` calls `sys.exit()` directly. Embedding this in a web worker risks killing the worker process and requires monkeypatching core control flow just to get it to return instead of loop/exit. |
| Full refactor of PRET into an importable, non-interactive service first | **Rejected for v1** | Valuable long-term, but violates working rule #7 (preserve existing functionality unless justified) and rule #3 (smallest architecture) for a first version. Revisit in a later phase once the adapter layer proves which specific calls are actually needed. |
| Controlled subprocess per assessment job | **Adopted** | PRET already has a working CLI contract (`pret.py <target> <mode> [-i loadfile] [-o logfile] [-q] [-s]`) designed for exactly this: non-interactive use via `-i`/`--load` to feed a command file and `-q` to suppress interactive chatter. This reuses PRET unmodified, isolates each session's blocking I/O in its own OS process (so a hung/slow printer can't block the web server), and gives a natural place to enforce timeouts (kill the process) and resource limits. |
| Hybrid: subprocess for the interactive language shells (PJL/PCL/PS), thin direct-import wrappers for the already-standalone probes (`capabilities.py`, `discovery.py`) | **Adopted alongside the above** | `capabilities.py` and `discovery.py` are not `cmd.Cmd`-based, don't block on stdin, and don't call `sys.exit()`. They're safe to import and call directly from the backend for fast, structured discovery/capability checks, with a short explicit timeout already built into `capabilities.timeout`. |

So concretely: **two integration paths**, matched to what each piece of code
actually is (per the Phase 1 findings), not one blanket strategy.

### Path A — subprocess wrapper for PJL/PCL/PostScript assessment

- Backend writes a generated PRET command file (one command per line — the
  same format `do_load` already parses) to a job-scoped temp directory.
- Backend launches `python3 pret.py <target> <mode> -q -i <cmdfile> -o
  <logfile>` as a subprocess with:
  - `stdin` closed/redirected from `/dev/null` (PRET never needs interactive
    input in this mode because every command is pre-loaded).
  - a hard wall-clock timeout, enforced by the job runner (not by PRET,
    which has no such concept) — if exceeded, terminate the process group.
  - `cwd` pinned to PRET's own directory so its relative `db/`, `mibs/`
    lookups keep working.
  - output captured from the `-o` logfile plus captured stdout/stderr,
    then parsed into the structured result model (`07-DATA-MODEL-AND-MEMORY.md`).
- The **command file itself is backend-generated from a fixed catalog of
  supported operations** (see `06-PROTOCOL-ADAPTER-DESIGN.md`), never from
  raw user text. The browser selects an operation (e.g. "list PJL
  variables", "check default password", "dump filesystem listing") and
  parameters go through validation — it never gets a free-text field that
  becomes a PRET command line.
- `do_exit`'s `sys.exit()` is harmless here because PRET is the entire
  subprocess; exiting is just the subprocess ending.

### Path B — direct import for discovery/capability probing

- `capabilities.capabilities(args)` and `discovery.discovery()` /
  `discovery(True)` can be called in-process (ideally inside the same
  worker-process model as Path A, still not the main request-handling
  thread/process — see below) since they return/print structured-enough
  data and don't take over the controlling terminal.
- Their `requests`/`urllib3` calls (`capabilities.py`) must still go through
  the backend's own SSRF/LAN-scope validation (`05-SECURITY-ARCHITECTURE.md`)
  before being invoked — importing the module doesn't exempt it from
  target validation.

### What's reused unmodified vs. needs an adapter vs. needs refactoring

| PRET component | Treatment |
|---|---|
| `pjl.py`, `pcl.py`, `postscript.py`, `printer.py` core command set | Reused unmodified, driven via Path A (subprocess + command file) |
| `helper.py` (`conn`, `output`, `log`, `const`) | Reused unmodified, internal to the subprocess |
| `capabilities.py` | Reused via direct import (Path B), wrapped by backend-side timeout/validation |
| `discovery.py` | Reused via direct import (Path B); **note** its SNMP dependency is optional — the adapter must report "SNMP discovery unavailable" rather than fail silently (see Phase 1 finding on `snmp_modules_found`) |
| `do_fuzz` / filesystem traversal commands | Reused via Path A, but gated: these are state-probing but can be noisy/slow; exposed as an explicit, confirmable "deep filesystem audit" operation, not part of default inventory |
| `print` command (ImageMagick/Ghostscript conversion) | **Not exposed in v1.** PRET's own code comments flag this as carrying known CVE-class risk when fed untrusted files; there's no product requirement for driverless printing in a security-assessment tool. Documented as explicitly disabled rather than silently omitted. |
| `edit` command (`subprocess.call([self.editor, ...])`) | **Not exposed.** Meaningless outside an interactive terminal; would require re-implementing an in-browser editor anyway, which is a distinct, separate feature if ever wanted. |
| `console.py` (ncurses results browser) | **Not reused.** Terminal-only by construction (`npyscreen`); the web UI's "Enumeration"/results views replace its purpose entirely. |
| LPD (`lpd/` scripts) | **Not reused as-is** — not part of `pret.py` at all; if LPD support is wanted (see Phase 3), it needs a new adapter, not an import of these standalone scripts, which were written as one-off test tools. |

## Recommended architecture shape (smallest that fits the requirements)

```
Browser (UI)
   │  HTTPS, LAN-restricted
   ▼
Web backend (Python, e.g. FastAPI or Flask)
   ├─ REST endpoints: printers, scans, jobs, findings, logs, auth
   ├─ Job runner (in-process worker pool, not a separate message-broker
   │  service — see justification below)
   │     ├─ Path A: subprocess-driven PRET sessions (PJL/PCL/PS)
   │     └─ Path B: direct-import capability/discovery probes
   ├─ SQL database (schema in 07-DATA-MODEL-AND-MEMORY.md)
   └─ WebSocket/SSE endpoint: job progress + live log streaming
```

Justification for **not** adding a separate message broker (Celery/RabbitMQ/
Redis queue) in v1: expected concurrency is "a handful of printers on one
LAN, assessed by one small team," not a multi-tenant SaaS scale. An
in-process worker pool (e.g. a bounded `ThreadPoolExecutor` or
`asyncio` + `subprocess` tasks) with a DB-backed job table gives
durability (jobs survive a request, are listed/cancelled via the API) and
concurrency limits without a new infrastructure dependency. This can be
revisited explicitly later if real usage shows the backend process itself
needs to be horizontally scaled — that's an `09-ROADMAP.md` open question,
not a day-one requirement.

WebSockets/SSE are justified specifically by the dashboard mockup's "Recent
Logs" live feed and per-job progress — this is a real, named requirement,
not an added-because-trendy component.

## Summary answer to "which of the four integration models"

**Hybrid**, split by what the code actually is: subprocess for the
interactive language shells, direct import for the two already-headless
probe modules. This is the only option consistent with Phase 1's findings
without either rewriting PRET (violates rule #7/#3) or trying to embed a
`cmd.Cmd` REPL into a request handler (would require defeating PRET's own
exit/blocking control flow).
