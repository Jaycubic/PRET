# Phase 4 — Linux Deployment and Windows Portability

## Platform-dependent assumptions audited

| Area | Linux assumption | Windows reality | Mitigation |
|---|---|---|---|
| Subprocess invocation | `subprocess.Popen([...])` argument-list form (already used by PRET for `convert`) | Argument-list form works identically on Windows via `CreateProcess`; avoid `shell=True` everywhere (PRET already does) | Keep using list-form subprocess calls in the new backend code; never introduce `shell=True` |
| Process termination / timeouts | `os.killpg`/process groups for killing a subprocess tree on timeout | No process groups on Windows; use `subprocess.Popen(..., creationflags=CREATE_NEW_PROCESS_GROUP)` + `proc.terminate()`/`taskkill` equivalent, or prefer `psutil` for a cross-platform kill-tree helper | Isolate process lifecycle management behind one small `job_process.py` module with an `if os.name == "nt"` branch, not scattered across the codebase |
| Temp files/dirs | `/tmp`, `os.path.exists`+`stat.S_ISCHR` for char devices (local/USB printer target) | `tempfile.gettempdir()` already resolves correctly cross-platform; the char-device branch in `conn.open()` is Linux/Unix-specific (Windows doesn't expose printers as `/dev/*` char devices) | Treat "local character-device target" as a Linux-only feature, explicitly documented as unavailable on Windows (network targets work identically on both) |
| Paths | PRET's own path handling already imports both `ntpath` and `posixpath` (`printer.py`) for building traversal payloads targeted at the *printer's* filesystem, not the host's | No change needed — that's about the remote device's OS, not the host | For backend-side paths (job workdirs, logs, DB file), always use `pathlib.Path` / `os.path.join`, never hardcoded `/` or `\\` |
| Sockets / network interface discovery | Raw `socket` module behaves the same cross-platform for the raw-TCP, LPD, IPP cases | SO_REUSEADDR/broadcast socket options have minor Windows quirks; `pysnmp`'s `asyncore` dispatcher used for discovery works on both but broadcast discovery may need the Windows Firewall to allow inbound UDP replies | Document the required inbound-UDP firewall allowance for discovery as a Windows deployment note; test broadcast discovery explicitly on Windows CI (see `08-TESTING-STRATEGY.md`) |
| Firewall / binding | Binding the web server to a LAN-only interface (not `0.0.0.0`) is the default-deny posture either way | Same logic applies; Windows Defender Firewall inbound rule needed if accessed from other LAN hosts | Document explicit bind-address configuration in both the Linux systemd unit and the Windows service wrapper |
| External executables | ImageMagick/Ghostscript (`convert`) only needed for the `print` command | Both have Windows builds, but **this feature is not exposed in v1** (see `02-INTEGRATION-STRATEGY.md`) | No action needed unless `print` is revisited later; if so, require explicit install-time detection + graceful "feature unavailable" rather than a hard crash |
| Service management | systemd unit, `User=`/`Group=` for an unprivileged service account | Windows Service (via `pywin32`/NSSM) or simply "run as a scheduled, logged-in-session process" for smaller deployments | Provide both a systemd unit file and documented Windows service setup; do not assume systemd is universal |
| Encoding / console output | PRET's `colorama`-based colored output assumes an ANSI-capable terminal; irrelevant once output is captured and re-rendered by the web UI instead of printed to a console | Same — once subprocess stdout is captured programmatically rather than displayed in a terminal, platform console differences disappear | Capture subprocess output as bytes/text, strip ANSI codes if any leak through (`colorama`'s `AnsiToWin32` only matters for literal terminal display, not for a backend reading pipes) |
| Privilege level | No privilege needed to open outbound sockets to port 9100/515/631/161/80/443, or to run as an ordinary user | Same — no admin rights needed for outbound connections | Document explicitly: **the service must never request/require root or Administrator.** The only operation that would need elevation (binding to a port < 1024 for the web UI itself) is avoided by defaulting to a high port (e.g. 8443) behind a reverse proxy if port 443 is wanted |

## Deployment model

### Linux (primary target)

- Python 3.11+ in a dedicated virtual environment (`python -m venv`), **not**
  system Python, to keep PRET's dependencies (`requests`, `urllib3`, the
  maintained `pysnmp` fork, `zeroconf`) isolated and reproducible via a
  pinned `requirements.txt` (the current PRET repo has none — one must be
  authored as part of this project, pinning exact versions).
- Runs as a dedicated, unprivileged system account (e.g. `pretweb`), with
  its own home/working directory for job temp files, logs, and the SQLite
  (or Postgres) database file — never as `root`.
- systemd unit with `Restart=on-failure`, `ProtectSystem=strict`,
  `NoNewPrivileges=true`, a narrow `ReadWritePaths=` limited to the app's
  data directory, and `User=`/`Group=` set to the dedicated account.
- Docker is **optional**, offered as one deployment path (useful for
  reproducibility and for isolating the ImageMagick/Ghostscript dependency
  if that feature is ever re-enabled) — not mandated, since a LAN-restricted
  internal tool run via systemd + venv is equally valid and simpler to
  reason about for the "must not be internet-exposed" requirement.
- Logging: structured (JSON lines) application log via Python's standard
  `logging` module to a rotating file handler (`logging.handlers
  .RotatingFileHandler` or systemd's own journal + `journald` rotation/
  retention policy if deployed that way) — separate from the per-job PRET
  session logs stored in the database (see `07-DATA-MODEL-AND-MEMORY.md`).
- Health check: a `/healthz` endpoint that checks DB connectivity and
  reports job-worker liveness, for use by systemd `ExecStartPost`/a
  monitoring probe — not a feature PRET itself has any equivalent of.

### Windows (portability target, not primary)

- Same Python version and pinned `requirements.txt` inside a venv created
  with `python -m venv`.
- Run as a Windows Service via a small wrapper (e.g. `pywin32`'s
  `win32serviceutil`, or a simpler "Scheduled Task at logon" for smaller/
  dev deployments) under a dedicated local service account — not
  `LocalSystem`/Administrator.
- The local character-device printer target (USB-attached, Linux-only
  branch in `conn.open()`) is explicitly **not available** on Windows;
  document this rather than attempting to fake parity.
- SNMP broadcast discovery and mDNS both require the relevant inbound UDP
  allowance in Windows Defender Firewall — document as a setup step.

## Dependency and vulnerability management

- Author a `requirements.txt` (absent in upstream PRET) pinning exact
  versions for: the maintained `pysnmp` fork, `zeroconf`, `requests`,
  `urllib3`, `colorama`, plus the new backend's own dependencies (web
  framework, ORM, etc.) — see `07-DATA-MODEL-AND-MEMORY.md` for backend
  choices.
- Run `pip-audit` (or equivalent) in CI against the pinned requirements file
  as part of the testing strategy (`08-TESTING-STRATEGY.md`), not as a
  manual, easily-skipped step.
- Treat ImageMagick/Ghostscript as **not a dependency of v1** at all, since
  the `print` feature that needs them is disabled (per `02-INTEGRATION-
  STRATEGY.md`) — this also removes the CVE-2016-3714/-7976-class risk
  PRET's own code comments flag, simply by not shipping that code path.

## Platform abstraction layer

Recommended: one module, `platform_ops.py`, that is the **only** place in
the new backend code allowed to branch on `os.name`/`sys.platform` or call
a platform-specific API — covering process-tree termination, default temp/
data directory resolution, and service-account/privilege checks. Everything
else in the codebase calls into this module rather than re-implementing
platform checks inline, so portability bugs have one place to be found and
fixed.
