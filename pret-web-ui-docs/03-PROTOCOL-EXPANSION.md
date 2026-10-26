# Phase 3 — Protocol and Discovery Expansion

Categories, kept distinct per the brief:
- **Printer languages** (what the document/command stream is written in): PJL, PCL, PostScript.
- **Transport protocols** (how bytes get to the device): raw TCP/9100, LPD/LPR, IPP/IPPS (also carries documents).
- **Management/monitoring protocols**: SNMP, HTTP(S) admin interfaces, manufacturer APIs.
- **Discovery mechanisms**: SNMP broadcast (already used), mDNS/DNS-SD.

## Expansion matrix

| Protocol | Purpose | PRET support today | Integration approach | Use case fit | Risk / complexity | Linux | Windows | Priority |
|---|---|---|---|---|---|---|---|---|
| PJL | Printer language: variables, filesystem, status | Full (`pjl.py`) | Reused as-is via Path A | Inventory + active assessment | Low risk, already battle-tested | Yes | Yes (pure Python/sockets) | Already have |
| PostScript | Printer language: filesystem, code execution surface | Full (`postscript.py`) | Reused as-is via Path A | Active assessment (higher-impact findings) | Medium — PS can read/write files, run amok on some devices; keep behind confirmation | Yes | Yes | Already have |
| PCL | Printer language: limited compared to PJL/PS | Full (`pcl.py`) | Reused as-is via Path A | Inventory + basic assessment | Low | Yes | Yes | Already have |
| Raw TCP / port 9100 | Transport for PJL/PCL/PS | Full (`helper.conn`, default port) | Reused as-is | Core transport | Low | Yes | Yes | Already have |
| SNMP v1/v2c | Device identity, status, interpreter/capability discovery, local-net discovery | Partial — v1 only, optional dependency (`discovery.py`, `capabilities.py`) | Replace the unmaintained `pysnmp` dependency with the actively maintained `pysnmp` fork now published under the original `pysnmp` name on PyPI (formerly distributed as `pysnmp-lextudio`; the original author is deceased and upstream `etingof/pysnmp` is unmaintained) — see https://pypi.org/project/pysnmp/ and https://github.com/lextudio/pysnmp | Read-only inventory (device description, uptime, supply levels) | Low-medium; SNMP community strings may be default/weak — flag as a finding, don't brute-force by default | Yes | Yes (pure Python) | High — fixes an existing silent-degradation bug |
| SNMPv3 | Authenticated/encrypted SNMP | **Not implemented** (PRET explicitly uses v1 "because most widely supported") | New adapter using the same maintained `pysnmp` library (it supports v3 USM auth/priv) | Configuration auditing with credentials the assessor already holds | Medium complexity (auth/priv protocol negotiation); never store community strings/credentials beyond job scope | Yes | Yes | Medium — add once v1/v2c path is solid |
| IPP | Modern print submission + rich `get-printer-attributes` introspection | Partial — `capabilities.py` only queries `printer-description` for capability probing, no general IPP client | New adapter using a maintained IPP client library (evaluate `pyipp`/`ipp` packages on PyPI at build time; confirm current maintenance status before pinning) over the existing `requests`/`urllib3` the project already depends on if a dedicated client proves unnecessary | Rich read-only inventory (make/model, supply levels, supported document formats, security attributes like `printer-uri-security-supported`) | Low-medium | Yes | Yes | High |
| IPPS | IPP over TLS | Not implemented | Same adapter as IPP with TLS; **explicit, validated certificate handling** — do not blanket-disable verification the way `capabilities.py` currently disables `InsecureRequestWarning` for HTTPS probing (Phase 1 finding); offer "accept self-signed on this LAN target" as an explicit, audited choice, not a silent default | Same as IPP, with transport confidentiality | Low-medium | Yes | Yes | High (paired with IPP) |
| HTTP/HTTPS admin UI | Vendor web management interface: status pages, sometimes config/firmware endpoints | Partial — `capabilities.py` fetches an HTML title and little else | New lightweight adapter: fetch root page banner/title/server header for fingerprinting (read-only), and a small, explicit catalog of known-path checks (e.g. default-credential pages) — never a generic "fetch any URL/path" endpoint | Inventory (fingerprinting) now; configuration auditing later once specific, vetted per-vendor checks exist | Medium — this is the most "it depends on the printer brand" surface, and the most SSRF-sensitive one (full URL-shaped target) | Yes | Yes | Medium |
| mDNS / DNS-SD | LAN discovery of `_ipp._tcp`, `_printer._tcp`, `_pdl-datastream._tcp` services | **Not implemented** | New adapter using `python-zeroconf` (`pip install zeroconf`), a pure-Python, actively maintained, cross-platform library — https://github.com/python-zeroconf/python-zeroconf / https://pypi.org/project/zeroconf/ | Read-only discovery, complements SNMP broadcast discovery (catches printers that don't answer SNMP) | Low | Yes | Yes (no native mDNS daemon dependency needed; doesn't require Bonjour/Avahi system service) | High — closes a real discovery gap, low cost |
| LPD/LPR | Legacy print transport, port 515 | **Not wired into `pret.py` at all** — only standalone, unmaintained scripts in `lpd/` | If wanted: new adapter built against RFC 1179 directly (small protocol) or a maintained library if one is actively maintained at build time; do not resurrect `lpd/lpdprint.py`/`lpdtest.py` as-is — they're disconnected test scripts, not production code | Low priority — legacy, increasingly rare, limited assessment value beyond "is the port open" | Low complexity, low value | Yes | Yes | Low |
| Manufacturer-specific management APIs (e.g. vendor REST APIs on some enterprise MFPs) | Deeper config/firmware info on specific device families | Not implemented, not generic | Would require a per-vendor adapter, only worth building once specific target hardware is known | Configuration auditing on known fleets only | High complexity, vendor lock-in, fragile across firmware versions | Varies | Varies | Not now — revisit only if a specific customer fleet justifies it |

## What to build, in order, and why

1. **mDNS/DNS-SD discovery** (new) + **SNMP discovery/capability fix** (swap the
   dependency) — both are read-only, low-risk, and directly improve the
   "Discovered Printers" experience shown in the dashboard mockup, which
   today only reflects manually-added IPs.
2. **IPP/IPPS read-only inventory** — the single highest-value new signal
   source (rich structured attributes without needing SNMP community
   strings), and a natural fit for the existing "Device Information" panel.
3. **SNMPv3** — once v1/v2c inventory is solid and there's a real need to
   audit devices that have v1/v2c disabled (increasingly common on hardened
   fleets).
4. **HTTP(S) admin fingerprinting**, starting read-only (banner/title only),
   expanding to specific vetted default-credential/config checks later,
   each added deliberately rather than as a generic URL fetcher.
5. **LPD** — low priority, small effort, can be picked up opportunistically.
6. **Manufacturer-specific APIs** — explicitly deferred, not scheduled.

## Sources consulted

- `pysnmp` maintenance status and the `lextudio` fork (https://pypi.org/project/pysnmp/, https://github.com/lextudio/pysnmp) — original author is deceased; the fork is the actively maintained continuation and now also ships SNMPv3 and asyncio support.
- `python-zeroconf` (https://pypi.org/project/zeroconf/, https://github.com/python-zeroconf/python-zeroconf) — pure-Python mDNS/DNS-SD, no native OS daemon dependency, confirmed cross-platform.
- IPP client library choice is flagged as **verify-at-build-time** rather than pinned here, since PyPI package health for small IPP client libraries changes faster than this document should be treated as authoritative; the agent must re-check before pinning a version.
