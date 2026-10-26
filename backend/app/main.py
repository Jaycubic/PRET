"""
App entrypoint. Binds LAN-only by default (see config.bind_host) and
serves the built frontend as static files from the same process — one
deployable unit, per 04-DEPLOYMENT-PORTABILITY.md / "smallest
architecture" principle.
"""
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import settings
from .db import init_db, SessionLocal, User
from .security import hash_password
from .routes import auth, devices, jobs, adapters, settings_routes, audit, discovery
from . import ws

app = FastAPI(title="PRET Web UI", version="0.1.0")

# Dev convenience only: allows a separately-running Vite dev server
# (localhost:5173) to call the API during frontend development. In
# production the frontend is served by this same process, so CORS is
# irrelevant there.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(jobs.router)
app.include_router(adapters.router)
app.include_router(settings_routes.router)
app.include_router(audit.router)
app.include_router(discovery.router)
app.include_router(ws.router)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


def bootstrap_admin() -> None:
    """
    Creates a default admin account ONLY if no users exist yet, using
    credentials from the environment (never hardcoded). Prints a loud
    warning if falling back to the insecure built-in default — this is
    meant to be changed immediately on first login, as README.md states.
    """
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        username = os.environ.get("PRETWEB_ADMIN_USER") or settings.pretweb_admin_user
        password = os.environ.get("PRETWEB_ADMIN_PASSWORD") or settings.pretweb_admin_password
        if not password:
            password = "change-me-now"
            print(
                "\n*** WARNING: no PRETWEB_ADMIN_PASSWORD set. Created admin "
                "account 'admin' / 'change-me-now'. Change this immediately. ***\n"
            )
        db.add(User(username=username, password_hash=hash_password(password), role="admin"))
        db.commit()
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    init_db()
    bootstrap_admin()


# Serve the built frontend (frontend/dist, copied to backend/app/static by
# the build process — see ../README.md "Build & run"). Mounted last so it
# doesn't shadow the /api and /ws routes above.
_static_dir = Path(__file__).resolve().parent / "static"
if _static_dir.exists():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")
