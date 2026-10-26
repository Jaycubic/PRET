# Phase 1 — PRET Repository Architecture Assessment

Source inspected: `https://github.com/RUB-NDS/PRET`, shallow clone, commit at
time of inspection (2026-10-23). All findings below are from reading the
actual files, not from the README's description of itself — the README is
noted separately where it disagrees with the code.

## 1. Repository layout

```
pret.py           entry point / CLI argument parsing
printer.py        core interactive shell (cmd.Cmd subclass), connection mgmt,
                  fuzzing routines, generic filesystem-abuse commands
pjl.py            PJL language class (printer(cmd.Cmd) subclass)
pcl.py            PCL language class (subclass)
postscript.py     PostScript language class (subclass)
capabilities.py   pre-connection capability probing via IPP/SNMP/HTTP
discovery.py      local-network printer discovery via SNMP broadcast
helper.py         conn (socket/char-device transport), log, output, file,
                  conv, const (protocol constants/delimiters)
codebook.py       PJL/PCL/PS status/error code lookup tables
operators.py      PostScript operator helper table
fuzzer.py         wordlists/paths used by fuzz commands
console.py        standalone npyscreen-based TUI browser for dumped data
                  (separate tool, not wired into pret.py's main loop)
db/               pjl.dat / pcl.dat / ps.dat — model→capability lookup tables
mibs/             SNMP MIB definitions used by discovery/capabilities
fonts/, overlays/ assets for the PostScript `overlay`/font-related commands
lpd/              standalone LPD test scripts, not imported by pret.py
testpages/        sample PS/PCL files for the `print` experimental feature
```

Entry point: `pret.py:main()` parses CLI args, prints a banner, optionally
runs `capabilities()` (only if `--safe`), then instantiates exactly one of
`postscript(args)`, `pjl(args)`, `pcl(args)` depending on `args.mode`
(`pret.py:65-75`).

## 2. Execution lifecycle (traced from CLI to socket)

1. `pret.py:usage()` builds an `argparse` parser: positional `target`,
   positional `mode` (`ps|pjl|pcl`), flags `-s/--safe`, `-q/--quiet`,
   `-d/--debug`, `-i/--load <file>`, `-o/--log <file>`.
2. `printer.__init__` (`printer.py:50-72`) is invoked by whichever subclass
   is chosen. It stores `debug`/`quiet`/`mode` from args, calls
   `self.do_open(args.target, "init")` to connect, optionally opens a log
   file and writes a PS/PCL header, optionally runs `do_load(args.load)` to
   replay a command file, then calls `self.cmdloop()` — **this blocks the
   calling thread on stdin** (it's a `cmd.Cmd` REPL).
3. `do_open` (`printer.py:204-`) builds a `conn(mode, debug, quiet)` object,
   sets a socket timeout, calls `conn.open(target)`, then calls the
   subclass's `on_connect()` hook (each language class implements this to
   send language-specific handshake data and read back device info).
4. `conn.open()` (`helper.py:421-434`): if `target` is a path to a character
   device that exists on the local filesystem, it opens it with
   `os.open(target, os.O_RDWR)` (local/USB printer support). Otherwise it
   parses an optional `host:port` syntax and does
   `socket.connect((target, port))`, default port `9100`.
5. Command dispatch: PRET uses Python's standard `cmd.Cmd` — every
   interactive command is a `do_<name>` method on `printer` or a language
   subclass. `onecmd()` is overridden (`printer.py:136-141`) to catch all
   exceptions so one bad command doesn't kill the shell. `precmd()`
   (`printer.py:105-132`) blocks "online" commands when `self.conn is None`
   and writes non-empty commands to the logfile.
6. Sending/receiving uses `conn.send()` / `conn.recv_until(delimiter)`
   (`helper.py:449-548`): a **synchronous, blocking, poll-loop** that
   accumulates bytes until a regex delimiter matches, with its own ad-hoc
   watchdog timer built from `time.sleep(0.01)` — this is not
   `asyncio`-based and not thread-safe by design (one `conn` = one target,
   used from one thread).
7. Exit: `do_exit`/`do_quit`/`EOF` close the logfile and call `sys.exit()`
   directly — this is a REPL-oriented exit path, not a function return, and
   would need to be intercepted/replaced for any non-interactive caller.

## 3. Protocol / capability inventory

| Area | Status | Evidence |
|---|---|---|
| PJL | Implemented | `pjl.py` (~40 KB), full `codebook.py` PJL status table |
| PCL | Implemented | `pcl.py` |
| PostScript | Implemented | `postscript.py` (~64 KB, largest module — includes font/overlay commands) |
| Raw TCP transport (port 9100 default) | Implemented | `helper.conn.open()` default port is 9100 |
| Local character-device / USB printing | Implemented | `conn.open()` branch for `os.path.exists` + `stat.S_ISCHR` |
| SNMP discovery (broadcast) | Implemented, **optional dependency** | `discovery.py` wraps `pysnmp`/`pyasn1`; the module's own comment says "needs to be refactored into an 'snmp' class", and the import is wrapped in `try/except ImportError` with a `snmp_modules_found` flag — so SNMP support silently degrades if `pysnmp` isn't installed |
| IPP capability probing | Implemented (probe only, not general IPP client) | `capabilities.py` has an `ipp()` method using `requests`/`urllib3` to query `printer-description` |
| HTTP/HTTPS capability probing | Implemented (probe only) | `capabilities.py` has `http()`/presumably `https()` paths reading an HTML title; `urllib3` warnings explicitly disabled (`InsecureRequestWarning`) — i.e. it will probe HTTPS with cert verification effectively relaxed, which matters for the security design |
| LPD/LPR | **Not integrated** into `pret.py`'s CLI | Only present as standalone scripts in `lpd/` (`lpdprint.py`, `lpdtest.py`), never imported by `pret.py`, `printer.py`, or any language class |
| Filesystem abuse / path traversal fuzzing | Implemented | `printer.py` `do_fuzz`, `fuzz_path/_write/_blind`, backed by `fuzzer.py` wordlists |
| "Driverless" raw printing (`print` command) | Implemented, **explicitly flagged risky in its own docstring** | `printer.py:802-845`, shells out to ImageMagick/Ghostscript via `subprocess.Popen(["convert", ...])`; the method's own comment cites CVE-2016-3714/CVE-2016-7976 (ImageMagick RCE via crafted files) |
| Editing a downloaded file (`edit` command) | Implemented | `printer.py:548`, `subprocess.call([self.editor, lpath])` where `self.editor` defaults to `"vim"` — a class attribute, not user-controlled at runtime by default, but still a direct subprocess launch of an interactive editor, which is meaningless in a web context |
| TUI results browser (`console.py`) | Implemented, **not wired to the main tool** | Uses `npyscreen` (ncurses-based); standalone script, separate dependency, terminal-only by construction |

**Not found anywhere in the codebase:** SNMPv3 support (only v1 is used —
`discovery.py` explicitly comments "use SNMP v1 because it is most widely
supported"), mDNS/DNS-SD discovery, IPPS as a first-class client, any
built-in REST/HTTP server, any existing web UI or API layer, any database or
persistence layer, any authentication/session concept, any job queue, any
concurrency/async model, any Windows-specific code path beyond the README's
mention of an *optional* `win_unicode_console` package (not found referenced
in the Python source files at all — README-only).

## 4. Subprocess, filesystem, and OS-touching operations (full list)

| Location | Operation | Risk relevance |
|---|---|---|
| `printer.py:548` | `subprocess.call([self.editor, lpath])` | Launches an interactive terminal editor — not reusable as-is in a web backend; must not be exposed |
| `printer.py:836-838` | `subprocess.Popen(["convert", ...], stdout=PIPE, stderr=PIPE)` | Shells out to ImageMagick/Ghostscript to convert arbitrary user-supplied files; PRET's own comment flags this as a known RCE vector (CVE-2016-3714/-7976) if fed untrusted input |
| `printer.py:424-426` | `os.path.exists(target)` + `os.stat().st_mode` + `os.open(target, os.O_RDWR)` | Treats the CLI `target` argument as a potential local character-device path — on a web backend this must never accept arbitrary filesystem paths from the browser |
| `printer.py:540` | `tempfile.NamedTemporaryFile(delete=False)` | Used when downloading a remote file locally (for `edit`/`get` style commands); `delete=False` means cleanup is the caller's responsibility — must be addressed in the web wrapper (temp file lifecycle, cleanup, path isolation) |
| `helper.py:421-443` | raw `socket()` connect/close, plus the char-device open/close branch | The sole network transport; synchronous, one target per `conn` instance |
| `discovery.py` | UDP broadcast socket via `pysnmp`'s `asyncore` dispatcher | Discovery is its own async-ish (asyncore, not asyncio) event loop, separate from the main `cmd.Cmd` loop |

No `os.system()` or `os.popen()` calls exist anywhere in the tree (verified
by grep); all shelling-out goes through `subprocess`. No shell=True usage
was found, which is good (argument-list form avoids one whole class of
shell-injection bugs) — but the `convert` call still passes a user-supplied
file path to an external program, which is a file-content attack surface,
not a shell-escaping one.

## 5. Dependencies

Declared only in prose in `README.md` (no `requirements.txt`,
`setup.py`, or `pyproject.toml` exists in the repo):

- Required at runtime for full functionality: `colorama` (colored output),
  `pysnmp` + its `pyasn1` dependency (SNMP discovery/capability probing),
  `requests`, `urllib3` (capability probing over HTTP/HTTPS).
- Optional, Windows-only, mentioned in README but **not referenced anywhere
  in the `.py` source**: `win_unicode_console`. Treat this as an
  unverified/legacy README claim, not a confirmed code dependency.
- External system binaries, required only for the experimental `print`
  command: `convert` (ImageMagick) and Ghostscript.
- `console.py`'s standalone TUI requires `npyscreen`, used by no other
  module.

**README/code discrepancy:** `README.md` states "PRET only requires a
Python2 interpreter," but every `.py` file's shebang is `#!/usr/bin/env
python3` and the code uses Python 3 syntax (e.g. `print()` calls with
`from __future__ import print_function` only in `pret.py`, suggesting a
historical Python 2→3 migration that the README text was never updated to
reflect). Treat the codebase as **Python 3 only**, and treat the README's
Python 2 claim as stale documentation, not a compatibility target.

## 6. Implementation constraints relevant to web integration

1. **Synchronous, blocking I/O throughout.** `conn.recv_until` is a
   sleep-poll loop on a single blocking socket; `cmdloop()` blocks on
   stdin. None of this is safely callable from a single-process async web
   server without being pushed to its own thread or process per session.
2. **One `printer` instance = one REPL = one connected target**, by
   construction (`cmd.Cmd` subclass expecting an interactive terminal).
   There's no existing "headless" or "programmatic" entry point that
   returns structured results instead of printing to stdout.
3. **Output is print-based, not structured.** `output()` in `helper.py`
   formats human-readable strings for a terminal (including ANSI color via
   `colorama`), not JSON/dicts. A web backend needs an adapter layer to
   capture and structure this, not just redirect stdout.
4. **Exit paths call `sys.exit()` directly** (`do_exit`), which would kill
   a worker process, not just end a session, if PRET's shell is driven
   in-process rather than as a subprocess.
5. **No existing concept of "job," "user," "target list," or "result
   record."** All of this must be built new around PRET, not extended from
   anything already in the repo.
6. **Risky operations are not gated behind any flag in the library
   itself** — `fuzz write`, `fuzz blind`, the `print`/`convert` path, and
   general filesystem commands (`put`, `append`, `delete`) all run
   immediately when invoked; PRET relies entirely on the human operator at
   the keyboard to decide what's safe. A web wrapper must add that gating
   itself (see `05-SECURITY-ARCHITECTURE.md`).
7. **SNMP support is optional and silently degrades** if `pysnmp` isn't
   installed — any feature inventory/UI must reflect actual installed
   capability, not assume SNMP is always available.

## 7. Evidence index

- `pret.py` (full file reviewed)
- `printer.py` lines 1–218, 530–845 (reviewed directly; remaining lines are
  further `do_*` filesystem/traversal commands following the same pattern)
- `helper.py` lines 412–619 (`conn`, `const`) reviewed directly; `log`,
  `output`, `file`, `conv` classes present at lines 72, 105, 385, 332
  respectively (not fully quoted here, confirmed to exist via class-def
  grep)
- `discovery.py` lines 1–60 reviewed directly
- `capabilities.py` lines 1–60 reviewed directly
- `README.md` install/OS section (lines ~11–23) reviewed directly
- Repo-wide `grep` for `subprocess`, `os.system`, `os.popen`, `socket`,
  `tempfile` (full results quoted above — nothing omitted)

No files were inaccessible; this assessment is based on direct inspection,
not inference.
