"""
Intelligence and Threat Analysis API Routes.
Exposes deterministic finding normalization, offline KB lookups,
and Perplexity AI remediation report generation.
See PRET UI/UX Plan Phase 5.4.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db, Device, Result, IntelligenceReport, AuditLog, User
from ..deps import get_current_user
from ..intelligence.normalizer import normalize_device_results
from ..intelligence.client import generate_intelligence_report

router = APIRouter(prefix="/api/intelligence", tags=["intelligence"])


class GenerateReportRequest(BaseModel):
    api_key: str | None = None
    model: str = "sonar"


@router.get("/findings")
def get_all_findings(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Returns aggregated normalized findings across all registered devices."""
    devices = db.query(Device).all()
    all_findings: list[dict[str, Any]] = []

    for dev in devices:
        results = db.query(Result).filter(Result.device_id == dev.id).all()
        findings = normalize_device_results(dev.id, dev.ip_or_hostname, results)
        all_findings.extend(findings)

    return all_findings


@router.get("/findings/{device_id}")
def get_device_findings(
    device_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Returns normalized findings for a specific target device."""
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    results = db.query(Result).filter(Result.device_id == dev.id).all()
    return normalize_device_results(dev.id, dev.ip_or_hostname, results)


@router.post("/generate-report")
def create_report(
    body: GenerateReportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """
    Normalizes findings across all devices, synthesizes an executive
    remediation report (via Perplexity or offline KB), and persists it.
    """
    devices = db.query(Device).all()
    all_findings: list[dict[str, Any]] = []

    for dev in devices:
        results = db.query(Result).filter(Result.device_id == dev.id).all()
        findings = normalize_device_results(dev.id, dev.ip_or_hostname, results)
        all_findings.extend(findings)

    report_data = generate_intelligence_report(
        findings=all_findings,
        api_key=body.api_key,
        model=body.model,
    )

    db_report = IntelligenceReport(
        created_at=datetime.now(timezone.utc),
        created_by_user_id=user.id,
        model_used=report_data.get("model_used", "offline-kb"),
        fleet_risk_level=report_data.get("fleet_risk_level", "CLEAN"),
        executive_summary=report_data.get("executive_summary", ""),
        report_markdown=report_data.get("report_markdown", ""),
        structured_json=report_data,
    )
    db.add(db_report)
    db.add(
        AuditLog(
            user_id=user.id,
            action="generate_intelligence_report",
            outcome="success",
            detail=f"Report generated using {report_data.get('model_used')} with risk {report_data.get('fleet_risk_level')}",
        )
    )
    db.commit()
    db.refresh(db_report)

    return {
        "id": db_report.id,
        "created_at": db_report.created_at.isoformat(),
        "model_used": db_report.model_used,
        "fleet_risk_level": db_report.fleet_risk_level,
        "executive_summary": db_report.executive_summary,
        "report_markdown": db_report.report_markdown,
        "structured_json": db_report.structured_json,
    }


@router.get("/reports")
def list_reports(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Lists past intelligence reports."""
    reports = db.query(IntelligenceReport).order_by(IntelligenceReport.id.desc()).limit(20).all()
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat(),
            "model_used": r.model_used,
            "fleet_risk_level": r.fleet_risk_level,
            "executive_summary": r.executive_summary,
        }
        for r in reports
    ]


@router.get("/reports/{report_id}")
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieves a single intelligence report."""
    report = db.get(IntelligenceReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "id": report.id,
        "created_at": report.created_at.isoformat(),
        "model_used": report.model_used,
        "fleet_risk_level": report.fleet_risk_level,
        "executive_summary": report.executive_summary,
        "report_markdown": report.report_markdown,
        "structured_json": report.structured_json,
    }
