# Phase 8 — Final Assessment and Roadmap

## A. Executive summary

PRET is a mature, single-user, terminal-oriented Python 3 CLI tool
(`RUB-NDS/PRET`) for exercising PJL/PCL/PostScript printer languages over a
raw socket or local character device. It has no web layer, no database, no
job concept, no auth, and no async model of any kind — it's built entirely
around an interactive `cmd.Cmd` REPL that blocks on stdin and exits via
`sys.exit()`. Its SNMP-based discovery/capability probing is a secondary,
optional-dependency feature that silently degrades if `pysnmp` isn't
installed, and it has no LPD, IPP, mDNS, or SNMPv3 support despite some
README-level allusions. The most important architectural fact is that
PRET's actual code is safe and reusable largely unmodified *underneath* a
subprocess boundary, but cannot be sensibly embedded directly into a web
request/response cycle. The most important security fact is that nothing
in PRET itself enforces LAN-only scope, authorization, or safe-vs-
destructive operation separation — all of that must be built new, at the
web application layer, and enforced server-side rather than only in the
UI.

## B. Existing functionality — verified vs. assumed

**Verified** (read directly from source, file/line references in
`01-ARCHITECTURE-ASSESSMENT.md`): PJL/PCL/PostScript command sets; raw-TCP
and local-char-device transport; blocking recv-until-delimiter I/O;
`cmd.Cmd`-based REPL with `-i`/`-o`/`-q`/`-s`/`-d` CLI flags; filesystem
path-traversal fuzzing (`fuzz path/write/blind`); SNMPv1-only discovery
and capability probing behind an optional `pysnmp` import; IPP/HTTP(S)
capability *probing* (not general clients) with HTTPS certificate
verification warnings globally disabled; an experimental `print` command
that shells out to ImageMagick/Ghostscript and flags its own CVE-class
risk in a code comment; a standalone, disconnected `console.py` TUI and
disconnected `lpd/` test scripts that are not part of the main tool.

**Assumed / explicitly not confirmed, and not to be treated as fact going
forward:** the README's claim of Python 2 compatibility (contradicted by
every file's Python 3 shebang and syntax); the README's mention of
`win_unicode_console` (not referenced anywhere in the `.py` source); any
claim about PRET supporting SNMPv3, LPD, IPPS, or mDNS (it does not,
confirmed by absence).

## C. Integration strategy (full detail in `02-INTEGRATION-STRATEGY.md`)

Hybrid: PJL/PCL/PostScript assessment runs PRET **unmodified**, as a
subprocess driven via its existing `-i`/`-q`/`-o` non-interactive flags,
fed a backend-generated command file built only from a fixed, validated
operation catalog — never from free user text. Discovery and capability
probing (`discovery.py`, `capabilities.py`) are called by **direct
import**, since they're already headless and return in a bounded time.
This reuses PRET's real strength (the protocol-handling code) without
fighting its REPL/`sys.exit()` control flow, and keeps the smallest
possible new surface area: no message broker, no microservices, one
backend process with a bounded worker pool.

## D. Protocol expansion matrix

See the full table in `03-PROTOCOL-EXPANSION.md`. Summary priority order:
mDNS discovery + SNMP dependency fix (both read-only, closes real gaps) →
IPP/IPPS read-only inventory → SNMPv3 → HTTP(S) admin fingerprinting,
expanded deliberately → LPD (low priority) → manufacturer-specific APIs
(deferred indefinitely, no current justification).

## E. Security and portability risks, ranked

| Rank | Risk | Consequence if unaddressed |
|---|---|---|
| 1 (highest) | No server-side LAN-scope enforcement | The tool could be pointed at out-of-scope or external hosts; this is the single control the entire product's safety premise rests on |
| 2 | SSRF via HTTP(S)/IPP(S) redirects and DNS rebinding | An attacker-influenced printer admin page or DNS response could redirect the backend to internal services unrelated to printers |
| 3 | Exposing a generic command/URL endpoint to the browser | Would reintroduce arbitrary command/request execution, defeating every other control |
| 4 | Relaxed TLS verification carried over from PRET's `capabilities.py` pattern | Silent MITM exposure on HTTPS probing if not deliberately fixed |
| 5 | Unbounded retention of raw device output/credentials | Data-exposure risk and DB/memory growth; addressed by the caps and scrubbing in `07-DATA-MODEL-AND-MEMORY.md` |
| 6 | State-changing operations (fuzz write, filesystem delete) running without explicit confirmation | Could alter/damage real device state during what looked like routine inventory |
| 7 | Known-risky `print`/ImageMagick path | CVE-class RCE surface if ever re-enabled without hardening |
| 8 | Windows-vs-Linux process/termination/temp-file divergence | Resource leaks or failed cancellation specifically on Windows if the abstraction layer in `04-DEPLOYMENT-PORTABILITY.md` isn't actually used consistently |

## F. Proposed architecture

```
                 ┌───────────────────────────┐
                 │        Browser UI          │
                 └──────────────┬─────────────┘
                                 │ HTTPS (LAN-bound)
                 ┌──────────────▼─────────────┐
                 │   Web backend (FastAPI)     │
                 │  ┌───────────────────────┐  │
                 │  │ REST + WebSocket/SSE   │  │
                 │  └──────────┬────────────┘  │
                 │             │                │
                 │  ┌──────────▼────────────┐  │
                 │  │ Target validation layer│  │ <- 05-SECURITY-ARCHITECTURE.md
                 │  └──────────┬────────────┘  │
                 │             │                │
                 │  ┌──────────▼────────────┐  │
                 │  │ Bounded job worker pool│  │
                 │  │  ├─ PRET subprocess    │──┼──> raw TCP 9100 / char dev
                 │  │  │   (PJL/PCL/PS)      │  │
                 │  │  ├─ SNMP adapter       │──┼──> UDP 161/162
                 │  │  ├─ IPP/IPPS adapter   │──┼──> TCP 631 / 443
                 │  │  ├─ HTTP(S) adapter    │──┼──> TCP 80/443
                 │  │  └─ mDNS adapter       │──┼──> UDP 5353
                 │  └──────────┬────────────┘  │
                 │             │                │
                 │  ┌──────────▼────────────┐  │
                 │  │  SQLite / Postgres DB  │  │
                 │  └───────────────────────┘  │
                 └───────────────────────────┘
```

Execution lifecycle: UI selects a target + a catalog operation → backend
validates target against authorized scope → (if state-changing) requires
explicit confirmation → job row created (`queued`) → worker pool picks it
up → adapter runs (subprocess or direct call) with enforced timeout →
output streamed to DB (capped) and any open WebSocket → job finalized
(`succeeded`/`failed`/`timeout`/`cancelled`) → results normalized into the
common result model → audit log entry written throughout, not just at the
end.

Suggested project structure:

```
backend/
  app/
    adapters/          # one module per protocol, implementing the
                        # Phase 6 interface
    api/                # REST + WebSocket route handlers
    core/                # target validation, auth, job runner,
                        # platform_ops.py abstraction layer
    db/                  # SQLAlchemy models + migrations
    worker/              # job pool, subprocess lifecycle
  tests/
    unit/
    integration/
    fixtures/           # mock printer/SNMP/mDNS/HTTP test services
  requirements.txt
  pret/                 # vendored, UNMODIFIED upstream PRET checkout,
                        # invoked only via subprocess per 02-INTEGRATION-STRATEGY.md
frontend/
  ...                   # matches the provided dashboard mockup
```

## G. Phased implementation plan

1. **Minimal working version**: auth, device add/list, LAN-scope
   enforcement, PJL-only read-only inventory via the subprocess path,
   SQLite storage, basic dashboard matching the mockup's core tiles.
2. **Protocol expansion**: PCL/PostScript adapters, SNMP dependency fix +
   discovery, mDNS discovery, IPP/IPPS read-only inventory.
3. **Hardening**: full SSRF/redirect/DNS-rebinding protections, audit
   logging, confirmation flow for state-changing operations, credential
   encryption at rest.
4. **Deployment**: systemd packaging, Windows portability pass, CI matrix,
   dependency/vulnerability scanning in CI.
5. **Later, optional**: SNMPv3, deeper HTTP(S) admin checks, LPD.

## H. Open questions (answers would change the architecture)

1. Expected scale: one team on one LAN, or multiple teams/sites needing
   multi-tenancy? (Affects DB choice urgency and whether the worker pool
   ever needs to be more than one process.)
2. Is TLS termination handled by this app directly, or by an existing
   reverse proxy/load balancer in the deployment environment? (Affects
   whether the app needs its own cert management.)
3. Should hostnames be accepted as targets at all, or only raw IPs? (Fully
   disabling hostname targets removes the DNS-rebinding attack surface
   entirely rather than just mitigating it — worth a deliberate decision
   rather than defaulting to "accept everything.")
4. Is there an existing identity provider (LDAP/SSO) to integrate with, or
   should the app own its own user table as designed here?
5. What's the actual retention requirement for audit logs and job
   history (compliance-driven, or purely operational)? This directly sizes
   the caps and purge policy in `07-DATA-MODEL-AND-MEMORY.md`.

## I. Evidence and references

- Repository inspected: `https://github.com/RUB-NDS/PRET` (shallow clone,
  2026-10-23) — see full file/line citations in
  `01-ARCHITECTURE-ASSESSMENT.md` §7.
- `pysnmp` maintenance status: https://pypi.org/project/pysnmp/,
  https://github.com/lextudio/pysnmp
- `python-zeroconf`: https://pypi.org/project/zeroconf/,
  https://github.com/python-zeroconf/python-zeroconf
- IPP client library choice intentionally left to be verified at build
  time rather than pinned in this document (see `03-PROTOCOL-EXPANSION.md`).
