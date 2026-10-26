from datetime import datetime, timezone
import json
import queue
import threading

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..adapters.port_scanner import scan_and_fingerprint_target
from ..adapters.registry import get_adapter
from ..db import get_db, Device, AuditLog, User, Job, Result
from ..deps import get_current_user
from ..schemas import DeviceCreate, DeviceOut
from ..security import resolve_and_validate, ScopeError, validate_port

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Device).order_by(Device.id.desc()).all()


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.get("/{device_id}/results")
def get_device_results(device_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return (
        db.query(Result)
        .filter(Result.device_id == device_id)
        .order_by(Result.id.desc())
        .limit(50)
        .all()
    )


@router.post("/{device_id}/probe")
def probe_existing_device(device_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    try:
        validated = resolve_and_validate(db, device.ip_or_hostname)
    except ScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    result = scan_and_fingerprint_target(validated.resolved_ip)
    if result.get("detected_model") and (not device.model or device.model == "Generic Printer"):
        device.model = result["detected_model"]
    if result.get("device_type"):
        device.device_type = result["device_type"]
    db.commit()
    db.refresh(device)
    return {"device": device, "probe": result}


@router.post("", response_model=DeviceOut)
def add_device(body: DeviceCreate, db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    try:
        validated = resolve_and_validate(db, body.ip_or_hostname)
        validate_port(body.port)
    except ScopeError as exc:
        db.add(AuditLog(user_id=user.id, action="add_device", outcome="failure", detail=str(exc)))
        db.commit()
        raise HTTPException(status_code=403, detail=str(exc))

    dev_type = body.device_type or "printer"

    device = Device(
        ip_or_hostname=body.ip_or_hostname,
        resolved_ip=validated.resolved_ip,
        port=body.port,
        model=body.model or "",
        device_type=dev_type,
        status="unknown",
        source="manual",
        added_by_user_id=user.id,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    db.add(AuditLog(user_id=user.id, action="add_device", target_device_id=device.id,
                     outcome="success", detail=f"{body.ip_or_hostname}:{body.port} ({dev_type})"))
    db.commit()
    return device


@router.post("/investigate-cups")
def investigate_cups_server(
    body: DeviceCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Seamless cyber security investigation of a particular IP hosting a CUPS print server.
    Enforces LAN scope authorization, registers/finds the print server device,
    and runs a full CUPS cyber audit (version, CVE-2024-47176/47076/47175/47177,
    admin auth & cupsd.conf exposure, and printer queue enumeration).
    """
    port = body.port or 631
    try:
        validated = resolve_and_validate(db, body.ip_or_hostname)
        validate_port(port)
    except ScopeError as exc:
        db.add(AuditLog(user_id=user.id, action="investigate_cups", outcome="failure", detail=str(exc)))
        db.commit()
        raise HTTPException(status_code=403, detail=str(exc))

    # Find existing device or create as print_server
    device = (
        db.query(Device)
        .filter(Device.resolved_ip == validated.resolved_ip, Device.port == port)
        .first()
    )
    if not device:
        device = Device(
            ip_or_hostname=body.ip_or_hostname,
            resolved_ip=validated.resolved_ip,
            port=port,
            device_type="print_server",
            status="unknown",
            source="cups_investigation",
            added_by_user_id=user.id,
        )
        db.add(device)
        db.commit()
        db.refresh(device)
    else:
        device.device_type = "print_server"
        db.commit()

    adapter = get_adapter("cups_server")
    if not adapter:
        raise HTTPException(status_code=500, detail="CUPS server adapter is not available")

    # Run the full cyber audit
    res = adapter.run_operation(
        "cups_full_audit",
        validated.resolved_ip,
        port,
        {},
    )

    # Record job & result in database for complete auditability
    job = Job(
        device_id=device.id,
        adapter_id="cups_server",
        operation_id="cups_full_audit",
        status="succeeded" if res.status == "ok" else "error",
        is_state_changing=False,
        confirmed=True,
        requested_by_user_id=user.id,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    db_res = Result(
        job_id=job.id,
        device_id=device.id,
        adapter_id="cups_server",
        operation_id="cups_full_audit",
        status=res.status,
        severity=res.severity,
        summary=res.summary,
        evidence_json=res.evidence or {},
        remediation=res.remediation,
        error_detail=res.error_detail,
    )
    db.add(db_res)

    # Update device metadata based on investigation findings
    if res.evidence and res.evidence.get("cups_version"):
        device.model = f"CUPS {res.evidence['cups_version']}"
    device.status = "online" if res.status == "ok" else "offline"
    device.last_seen_at = datetime.now(timezone.utc)

    db.add(AuditLog(
        user_id=user.id,
        action="investigate_cups",
        target_device_id=device.id,
        job_id=job.id,
        outcome="success" if res.status == "ok" else "failure",
        detail=f"CUPS investigation on {validated.resolved_ip}:{port} - {res.summary}",
    ))
    db.commit()

    return {
        "device": DeviceOut.model_validate(device),
        "job_id": job.id,
        "result": {
            "status": res.status,
            "severity": res.severity,
            "summary": res.summary,
            "evidence": res.evidence,
            "remediation": res.remediation,
        },
    }


@router.post("/exploit-verify-cups")
def exploit_verify_cups_stream(
    body: DeviceCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Real-time exploitation verification of a CUPS print server via Server-Sent Events.
    Streams each exploitation phase step as an SSE event for live terminal display.
    Tests CVE-2024-47176, CVE-2024-47076, CVE-2024-47175, CVE-2024-47177.
    """
    port = body.port or 631
    try:
        validated = resolve_and_validate(db, body.ip_or_hostname)
        validate_port(port)
    except ScopeError as exc:
        db.add(AuditLog(user_id=user.id, action="exploit_verify_cups", outcome="failure", detail=str(exc)))
        db.commit()
        raise HTTPException(status_code=403, detail=str(exc))

    # Ensure device exists
    device = (
        db.query(Device)
        .filter(Device.resolved_ip == validated.resolved_ip, Device.port == port)
        .first()
    )
    if not device:
        device = Device(
            ip_or_hostname=body.ip_or_hostname,
            resolved_ip=validated.resolved_ip,
            port=port,
            device_type="print_server",
            status="unknown",
            source="exploit_verification",
            added_by_user_id=user.id,
        )
        db.add(device)
        db.commit()
        db.refresh(device)

    adapter = get_adapter("cups_server")
    if not adapter:
        raise HTTPException(status_code=500, detail="CUPS server adapter is not available")

    resolved_ip = validated.resolved_ip
    device_id = device.id
    user_id = user.id

    # Thread-safe queue for SSE streaming
    event_queue: queue.Queue = queue.Queue()

    def progress_callback(msg: str):
        event_queue.put({"type": "progress", "data": msg})

    def run_verification():
        try:
            res = adapter.run_operation(
                "cups_exploit_verification",
                resolved_ip,
                port,
                {},
                progress_cb=progress_callback,
            )
            # Store result in DB
            from ..db import SessionLocal
            db2 = SessionLocal()
            try:
                job = Job(
                    device_id=device_id,
                    adapter_id="cups_server",
                    operation_id="cups_exploit_verification",
                    status="succeeded" if res.status == "ok" else "error",
                    is_state_changing=False,
                    confirmed=True,
                    requested_by_user_id=user_id,
                    started_at=datetime.now(timezone.utc),
                    finished_at=datetime.now(timezone.utc),
                )
                db2.add(job)
                db2.commit()
                db2.refresh(job)

                db_res = Result(
                    job_id=job.id,
                    device_id=device_id,
                    adapter_id="cups_server",
                    operation_id="cups_exploit_verification",
                    status=res.status,
                    severity=res.severity,
                    summary=res.summary,
                    evidence_json=res.evidence or {},
                    remediation=res.remediation,
                    error_detail=res.error_detail,
                )
                db2.add(db_res)

                db2.add(AuditLog(
                    user_id=user_id,
                    action="exploit_verify_cups",
                    target_device_id=device_id,
                    job_id=job.id,
                    outcome="success" if res.status == "ok" else "failure",
                    detail=f"Exploit verification on {resolved_ip}:{port} - {res.summary}",
                ))
                db2.commit()
            finally:
                db2.close()

            event_queue.put({
                "type": "complete",
                "data": {
                    "status": res.status,
                    "severity": res.severity,
                    "summary": res.summary,
                    "evidence": res.evidence,
                    "remediation": res.remediation,
                },
            })
        except Exception as exc:
            event_queue.put({"type": "error", "data": str(exc)})

    # Launch verification in background thread
    thread = threading.Thread(target=run_verification, daemon=True)
    thread.start()

    def event_generator():
        while True:
            try:
                event = event_queue.get(timeout=60)
            except queue.Empty:
                yield "event: keepalive\ndata: {}\n\n"
                continue

            event_type = event.get("type", "progress")
            event_data = event.get("data", "")

            if isinstance(event_data, dict):
                payload = json.dumps(event_data)
            else:
                payload = json.dumps({"message": str(event_data)})

            yield f"event: {event_type}\ndata: {payload}\n\n"

            if event_type in ("complete", "error"):
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

