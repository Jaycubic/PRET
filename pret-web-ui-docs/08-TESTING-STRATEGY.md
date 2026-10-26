# Phase 7 — Testing and Verification Strategy

No test in this suite connects to a real, production printer. Everything
below runs against mocks, simulated services, or loopback test fixtures.

## 1. Unit tests

- Target-validation logic (`05-SECURITY-ARCHITECTURE.md` §1-4): CIDR
  allow-list matching, IPv4/IPv6 parsing including link-local+scope-id
  handling, DNS-resolve-then-pin logic, port/scheme allow-listing —
  exhaustive table-driven cases including deliberately adversarial inputs
  (addresses just outside an allowed CIDR, IPv6-mapped-IPv4 forms,
  malformed scope IDs).
- Adapter operation-catalog validation: every declared operation's
  parameter schema rejects malformed/boundary input (path traversal
  sequences, oversized strings, wrong types) before a PRET command
  template is ever built.
- Result-model normalization: evidence truncation/size caps, severity
  mapping, credential-field scrubbing before anything is logged.

## 2. Integration tests using mocks/simulated printer services

- A lightweight raw-TCP/9100 test fixture that speaks just enough PJL/PCL/
  PostScript handshake and echo behavior (based on the delimiters/status
  codes documented in `helper.py`'s `const` class and `codebook.py`) to
  drive the PJL/PCL/PS adapters end-to-end without a real device — this
  fixture is authored as part of this project, not borrowed from PRET
  (PRET has no test fixtures of its own; Phase 1 found none).
- A mock SNMP agent (the maintained `pysnmp` fork ships agent/simulator
  support usable for this) for discovery and `capabilities.py`-path tests,
  including a negative case where the SNMP dependency is absent, asserting
  the adapter reports "unavailable" rather than crashing (directly
  regression-testing the Phase 1 finding about `snmp_modules_found`).
- A local mDNS registration (via `zeroconf`'s own service-registration API,
  used in a test to announce a fake `_ipp._tcp` service on loopback/test
  interface) to validate the discovery adapter without touching the real
  LAN.
- A minimal HTTP(S) test server (e.g. `http.server`/`aiohttp` test utils)
  for the HTTP(S) admin-fingerprinting adapter, including a redirect-chain
  fixture specifically to exercise the redirect-revalidation logic.

## 3. Protocol parsing and malformed responses

- Feed each adapter's parser truncated, corrupted, and adversarially
  malformed responses (not just well-formed ones) and assert graceful
  `status: error` results, never an unhandled exception that could crash
  a worker or leave a job stuck in `running`.

## 4. Connection timeouts and unavailable hosts

- A fixture that accepts a TCP connection and then never responds (and
  one that accepts then immediately resets), to verify both the socket-
  level timeout (PRET's own `conn.timeout`) and the job-level wall-clock
  timeout independently fire and clean up correctly.

## 5. Authorization boundary tests

- Attempt operations against devices/addresses outside the configured
  allow-list and assert rejection before any socket is opened (assert via
  a mock/spy that the underlying connect function was never called, not
  just that an error was eventually returned).
- Attempt role-gated actions (subnet config change, state-changing
  operation) as an `operator`-role user and assert rejection.

## 6. Command-injection and argument-validation tests

- Attempt to smuggle shell metacharacters, additional PRET commands
  (newline injection into a templated parameter), and path-traversal
  sequences through every operation parameter, asserting the generated
  PRET command file never contains anything beyond the validated,
  escaped value — this is the concrete regression test for the "no
  general-purpose shell" security rule.

## 7. SSRF and redirect-validation tests

- Redirect to loopback, to link-local metadata-style addresses (e.g.
  `169.254.169.254`), to a public address, and to a different port/scheme
  than allowed — assert each is blocked at the redirect-revalidation step,
  not only at the initial request.
- DNS-rebinding simulation: a test resolver that returns an allowed address
  on first lookup and a disallowed address on a second lookup, asserting
  the connection uses the pinned first-resolved address rather than
  re-resolving.

## 8. Concurrent job execution and cancellation

- Launch more jobs than the worker pool's concurrency limit and assert
  excess jobs queue rather than spawn unbounded subprocesses.
- Cancel a running job mid-flight and assert the underlying subprocess is
  actually terminated (not just marked cancelled in the DB) on both
  Linux and Windows process-termination code paths.

## 9. Linux deployment tests

- systemd unit starts under the unprivileged service account, passes the
  health check, and survives `systemctl restart` without orphaning
  subprocesses or temp directories (verifies the memory/lifecycle rules in
  `07-DATA-MODEL-AND-MEMORY.md` §5).

## 10. Windows compatibility tests

- Same core test suite run on a Windows CI runner (GitHub Actions
  `windows-latest` or equivalent), specifically covering: process-tree
  termination, temp directory resolution, the explicit "local
  character-device target unsupported" behavior, and SNMP/mDNS discovery
  under Windows Firewall's default inbound-UDP posture (documented
  separately if firewall config is required for discovery to pass in CI).

## 11. Regression tests for existing PRET functionality

- A small fixed set of "golden path" PJL/PCL/PS command sequences run
  against the mock printer fixture (§2), asserting PRET's own behavior
  (not the wrapper's) is unchanged after any dependency bump (e.g. the
  `pysnmp` fork swap) or Python version upgrade — this is what makes rule
  #7 ("preserve existing functionality unless justified") verifiable
  rather than just a promise.

## 12. CI matrix

| Axis | Values |
|---|---|
| OS | Linux (primary, full suite), Windows (portability suite per §10) |
| Python | the pinned minimum supported version + latest stable |
| Dependency set | pinned `requirements.txt` + `pip-audit` pass/fail gate |

No step in this matrix requires network access to anything outside the CI
runner's own loopback/test fixtures — this is a hard requirement, not an
aspiration, since it's what keeps "potentially destructive operations must
not run against real devices" true by construction.
