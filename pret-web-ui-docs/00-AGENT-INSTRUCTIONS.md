# PRET Web UI — Agent Instructions (Read First)

This folder is the working spec for building a browser-based printer security
assessment platform around **PRET** (Printer Exploitation Toolkit,
`RUB-NDS/PRET`). Any coding agent (Claude Code or otherwise) operating on this
project must read this file before writing or changing code, and must keep
behaving consistently with it for the rest of the project, not just the first
session.

## Reading order

1. `01-ARCHITECTURE-ASSESSMENT.md` — what PRET's code actually does today (verified, with file/line references).
2. `02-INTEGRATION-STRATEGY.md` — how the web app connects to that code.
3. `03-PROTOCOL-EXPANSION.md` — which additional protocols to add, and in what order.
4. `04-DEPLOYMENT-PORTABILITY.md` — Linux-primary / Windows-portable deployment rules.
5. `05-SECURITY-ARCHITECTURE.md` — LAN-only enforcement, SSRF defenses, auth, audit.
6. `06-PROTOCOL-ADAPTER-DESIGN.md` — the adapter interface every protocol module implements.
7. `07-DATA-MODEL-AND-MEMORY.md` — database schema, job/session memory management.
8. `08-TESTING-STRATEGY.md` — what must be tested and how, without touching real printers.
9. `09-ROADMAP.md` — phased build order and open questions.

## Non-negotiable working rules

These rules apply for the entire lifetime of the project, not just the first
message that introduces them:

1. **Inspect before implementing.** If a task touches a part of PRET or the
   web app that isn't already documented in `01-ARCHITECTURE-ASSESSMENT.md`,
   go read the actual source first. Do not infer behavior from filenames,
   README text, or training data about "how PRET probably works."
2. **No invented facts.** Never assert that PRET supports a protocol,
   function, or file that hasn't been verified in the current checkout.
   Mark anything uncertain as `ASSUMPTION` or `OPEN QUESTION`, not fact.
3. **Smallest architecture that meets the requirement.** Do not add a
   message queue, microservice, or new external dependency because it's
   common practice elsewhere — add it only when a concrete requirement in
   these docs needs it, and say which requirement.
4. **The browser never gets a shell.** No endpoint takes a free-form shell
   command, a free-form host/port with no validation, or a raw PRET command
   string without going through the adapter + validation layer in
   `06-PROTOCOL-ADAPTER-DESIGN.md`.
5. **LAN scope is enforced server-side**, not just hidden/labeled in the UI.
   See `05-SECURITY-ARCHITECTURE.md` for the exact checks required on every
   outbound connection the backend makes.
6. **State-changing operations require explicit confirmation** and are
   logged distinctly from read-only discovery/inventory operations.
7. **Existing PRET CLI functionality keeps working unmodified** unless a
   change is explicitly justified in writing (which file, which behavior,
   why). The web app should wrap/adapt PRET, not fork it silently.
8. **Platform parity by design.** Before adding any call to a shell command,
   external binary, or OS-specific API, check `04-DEPLOYMENT-PORTABILITY.md`
   for the cross-platform equivalent or the documented, isolated exception.
9. **Minimize sensitive data retention.** Don't persist full raw device
   output, credentials, or full file contents pulled from a printer unless
   a documented feature needs it — see `07-DATA-MODEL-AND-MEMORY.md`.
10. **Stop and ask when a change would affect architecture.** Anything in
    `09-ROADMAP.md`'s "Open questions" section should be resolved with the
    human operator before being implemented a particular way, not assumed.

## What "done" looks like for Phase 1 (already delivered here)

`01-ARCHITECTURE-ASSESSMENT.md` is the completed Phase 1 deliverable: a
findings report, not a redesign. Implementation work should not start until
a human has reviewed and approved the plan in `09-ROADMAP.md`.
