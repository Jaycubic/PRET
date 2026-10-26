"""
Network-wide discovery endpoint — distinct from the per-device job model
because a browse isn't aimed at one already-known target. Results are
merged into the devices table with source='mdns_discovery' (still
re-validated against the authorized-network allow-list before being
stored as reachable — discovery finding something does not imply it's
in scope to assess further).
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..adapters.mdns import browse_for_printers
from ..adapters.port_scanner import scan_and_fingerprint_target
from ..adapters.wsd import browse_for_wsd_printers
from ..db import get_db, Device, AuditLog, User
from ..deps import get_current_user
from ..schemas import ProbeRequest
from ..security import resolve_and_validate, ScopeError

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


@router.post("/mdns")
def run_mdns_discovery(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    try:
        services = browse_for_printers(timeout_seconds=5)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    added = []
    skipped_out_of_scope = []
    for svc in services:
        for addr in svc.get("addresses") or []:
            try:
                validated = resolve_and_validate(db, addr)
            except ScopeError:
                skipped_out_of_scope.append(addr)
                continue
            existing = db.query(Device).filter(Device.resolved_ip == validated.resolved_ip).first()
            if existing:
                continue
            device = Device(
                ip_or_hostname=addr,
                resolved_ip=validated.resolved_ip,
                port=svc.get("port") or 631,
                hostname=svc.get("server", ""),
                model=svc.get("properties", {}).get("ty", ""),
                status="unknown",
                source="mdns_discovery",
                added_by_user_id=user.id,
            )
            db.add(device)
            added.append(addr)

    db.commit()
    db.add(AuditLog(
        user_id=user.id, action="mdns_discovery", outcome="success",
        detail=f"found={len(services)} added={len(added)} out_of_scope_skipped={len(skipped_out_of_scope)}",
    ))
    db.commit()

    return {
        "found_services": len(services),
        "added_devices": added,
        "skipped_out_of_scope": skipped_out_of_scope,
    }


@router.post("/wsd")
def run_wsd_discovery(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    try:
        devices = browse_for_wsd_printers(timeout_seconds=3)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    added = []
    skipped_out_of_scope = []
    for item in devices:
        addr = item.get("address")
        if not addr:
            continue
        try:
            validated = resolve_and_validate(db, addr)
        except ScopeError:
            skipped_out_of_scope.append(addr)
            continue
        existing = db.query(Device).filter(Device.resolved_ip == validated.resolved_ip).first()
        if existing:
            continue
        device = Device(
            ip_or_hostname=addr,
            resolved_ip=validated.resolved_ip,
            port=5357,
            hostname=item.get("endpoint", ""),
            model=item.get("types", ""),
            status="unknown",
            source="wsd_discovery",
            added_by_user_id=user.id,
        )
        db.add(device)
        added.append(addr)

    db.commit()
    db.add(AuditLog(
        user_id=user.id, action="wsd_discovery", outcome="success",
        detail=f"found={len(devices)} added={len(added)} out_of_scope_skipped={len(skipped_out_of_scope)}",
    ))
    db.commit()

    return {
        "found_devices": len(devices),
        "added_devices": added,
        "skipped_out_of_scope": skipped_out_of_scope,
    }


@router.post("/probe")
def probe_target(body: ProbeRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """
    Scans standard printer ports (9100, 631, 515, 80, 443, 5357, 22),
    grabs protocol banners (PJL, IPP, HTTP), and returns detected services,
    accurate device type, model, and recommended port.
    Enforces scope validation — only authorized IP ranges can be probed.
    """
    try:
        validated = resolve_and_validate(db, body.ip_or_hostname)
    except ScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    result = scan_and_fingerprint_target(validated.resolved_ip, timeout=body.timeout)
    db.add(AuditLog(
        user_id=user.id,
        action="probe_ports",
        outcome="success",
        detail=f"target={body.ip_or_hostname} resolved={validated.resolved_ip} open_ports={result.get('open_ports')}",
    ))
    db.commit()
    return result

