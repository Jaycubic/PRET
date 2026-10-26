# Third-Party Licenses

## PRET (vendored, unmodified, under `pret/`)

This project bundles an unmodified checkout of **PRET (Printer
Exploitation Toolkit)**, originally by Jens Müller / RUB-NDS
(`https://github.com/RUB-NDS/PRET`), via `https://github.com/Jaycubic/PRET.git`.

- License: **GNU General Public License v2.0** — full text in `pret/LICENSE.md`
  and reproduced at the project root as `LICENSE`.
- PRET's own `pret/DISCLAIMER.md` states it is provided for academic and
  non-malicious purposes, "AS IS," with no warranty — reproduced in full
  in this project's own `DISCLAIMER.md`.
- **Why this whole project is licensed GPLv2 too:** PRET is invoked by
  this project's backend partly as a subprocess (`pret.py` driven via its
  own `-i`/`-q`/`-o` flags — see `pret-web-ui-docs/02-INTEGRATION-
  STRATEGY.md`) and, in planned future adapters, by direct Python import
  of PRET's `discovery.py`/`capabilities.py` modules into the same
  process. Subprocess invocation has a reasonable argument for not
  requiring the calling code to be GPL (the "mere aggregation" / separate-
  process position), but direct import is a much stronger "combined work"
  case under the GPL. **This project licenses all of its own new code
  (`backend/`, `frontend/`) under GPLv2 to stay unambiguously compliant
  either way, rather than relying on an interpretation that might not
  hold up.** If you plan to redistribute a modified version, keep this in
  mind — this is a licensing-hygiene decision, not legal advice; consult
  counsel if you have a specific redistribution plan that depends on the
  answer.

## Backend (Python) dependencies

See `backend/requirements.txt` for exact pinned versions. All are under
permissive (MIT/BSD/Apache-2.0) or LGPL licenses compatible with being
used alongside GPLv2 application code:

- FastAPI, Uvicorn, SQLAlchemy, Pydantic — MIT
- python-jose, passlib, bcrypt — MIT/BSD
- paramiko — LGPL-2.1
- python-dotenv, python-multipart — BSD/Apache-2.0

## Frontend (TypeScript/JavaScript) dependencies

See `frontend/package.json`. React and the Vite toolchain are MIT-licensed.

## Your obligations if you redistribute this project

Because of the GPLv2 licensing above: if you distribute binaries or a
packaged build of this project to others, you must also make the
corresponding source available to them under the same terms, and
preserve the copyright/license notices. This is a summary, not a
substitute for reading `LICENSE` in full.
