"""
Bounded job runner. See 07-DATA-MODEL-AND-MEMORY.md §5.
- Fixed-size worker pool (settings.max_concurrent_jobs).
- Job state is written to the DB throughout, not just at the end, so a
  backend restart loses only "what was running," not "what happened."
- Streams log lines to any attached WebSocket listeners AND to the
  capped evidence field — never buffers unboundedly.
- Opens/closes the SSH tunnel (if the target's authorized network has a
  route) strictly within the job's lifetime.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .adapters.registry import get_adapter
from .config import settings
from .db import SessionLocal, Job, Result, AuditLog, Device, NetworkRoute
from .security import resolve_and_validate, ScopeError, validate_port
from .tunnel import open_local_forward

_executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_jobs)
_listeners: dict[int, list] = {}  # job_id -> [callback(line)]
_listeners_lock = threading.Lock()


def subscribe(job_id: int, cb) -> None:
    with _listeners_lock:
        _listeners.setdefault(job_id, []).append(cb)


def _broadcast(job_id: int, line: str) -> None:
    with _listeners_lock:
        for cb in _listeners.get(job_id, []):
            try:
                cb(line)
            except Exception:
                pass


def submit_job(job_id: int) -> None:
    _executor.submit(_run_job, job_id)


def _run_job(job_id: int, db: Session | None = None) -> None:
    own_db = False
    if db is None:
        db = SessionLocal()
        own_db = True
    forward = None
    try:
        job = db.get(Job, job_id)
        if job is None:
            return

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        db.commit()
        _broadcast(job_id, f"job {job_id} started")

        device = db.get(Device, job.device_id) if job.device_id else None
        adapter = get_adapter(job.adapter_id)
        if adapter is None:
            raise RuntimeError(f"Unknown adapter {job.adapter_id}")

        dep = adapter.dependency_status()
        if not dep["available"]:
            raise RuntimeError(f"Adapter unavailable: {dep['detail']}")

        if device is None:
            raise RuntimeError("Job has no target device")

        validated = resolve_and_validate(db, device.ip_or_hostname)
        validate_port(device.port)
        job.route_id = validated.route_id
        db.commit()

        connect_ip = validated.resolved_ip
        connect_port = device.port

        if validated.route_id:
            route = db.get(NetworkRoute, validated.route_id)
            if route and route.is_enabled:
                _broadcast(job_id, f"opening tunnel via route '{route.name}'")
                forward = open_local_forward(route, validated.resolved_ip, device.port)
                connect_ip = "0.0.0.0"
                connect_port = forward.local_port
            else:
                raise ScopeError("Configured route is disabled or missing")

        def _validate_cb(host: str):
            # Lets an adapter validate a NEWLY-DISCOVERED host (e.g. a
            # redirect Location) against the same authorized-network
            # scope as the job's original target, using this job's own
            # db session. See base.py's ValidateCallback docstring and
            # 05-SECURITY-ARCHITECTURE.md §4.
            return resolve_and_validate(db, host)

        result = adapter.run_operation(
            job.operation_id,
            connect_ip,
            connect_port,
            job.params_json or {},
            progress_cb=lambda line: _broadcast(job_id, line),
            validate_cb=_validate_cb,
        )

        db.add(Result(
            job_id=job.id, device_id=job.device_id, adapter_id=job.adapter_id,
            operation_id=job.operation_id, status=result.status,
            severity=result.severity, summary=result.summary,
            evidence_json=result.evidence or {}, remediation=result.remediation,
            error_detail=result.error_detail,
        ))
        job.status = "succeeded" if result.status == "ok" else result.status
        job.finished_at = datetime.now(timezone.utc)
        db.add(AuditLog(
            user_id=job.requested_by_user_id, action=f"run:{job.adapter_id}:{job.operation_id}",
            target_device_id=job.device_id, job_id=job.id,
            outcome="success" if result.status == "ok" else "failure",
            detail=result.summary or result.error_detail,
        ))
        if device:
            device.status = "online" if result.status == "ok" else "offline"
            device.last_seen_at = datetime.now(timezone.utc)
            if job.adapter_id == "cups_server":
                device.device_type = "print_server"
                if result.evidence and result.evidence.get("cups_version"):
                    device.model = f"CUPS {result.evidence['cups_version']}"
        db.commit()
        _broadcast(job_id, f"job {job_id} finished: {job.status}")

    except ScopeError as exc:
        _fail_job(db, job_id, "error", str(exc))
        _broadcast(job_id, f"BLOCKED: {exc}")
    except Exception as exc:  # noqa: BLE001 - job runner must never crash the pool
        _fail_job(db, job_id, "error", str(exc))
        _broadcast(job_id, f"job {job_id} error: {exc}")
    finally:
        if forward is not None:
            forward.close()
        if own_db:
            db.close()


def _fail_job(db: Session, job_id: int, status: str, detail: str) -> None:
    job = db.get(Job, job_id)
    if job is None:
        return
    job.status = status
    job.finished_at = datetime.now(timezone.utc)
    db.add(Result(
        job_id=job.id, device_id=job.device_id, adapter_id=job.adapter_id,
        operation_id=job.operation_id, status="error", error_detail=detail,
    ))
    db.add(AuditLog(
        user_id=job.requested_by_user_id, action=f"run:{job.adapter_id}:{job.operation_id}",
        target_device_id=job.device_id, job_id=job.id, outcome="failure", detail=detail,
    ))
    db.commit()
