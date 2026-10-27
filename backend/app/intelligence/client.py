"""
Intelligence Client for Post-Assessment Reporting.
Calls Perplexity API when an API key is available; seamlessly falls back
to offline deterministic report generation when offline.
See PRET UI/UX Plan Phase 5.3.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import requests

from .redactor import redact_sensitive_data

_PROMPT_PATH = Path(__file__).parent / "prompts" / "remediation_system.md"
_SYSTEM_PROMPT: str = ""


def _get_system_prompt() -> str:
    global _SYSTEM_PROMPT
    if not _SYSTEM_PROMPT:
        if _PROMPT_PATH.exists():
            _SYSTEM_PROMPT = _PROMPT_PATH.read_text(encoding="utf-8")
        else:
            _SYSTEM_PROMPT = "You are an enterprise print security architect. Provide defensive remediation."
    return _SYSTEM_PROMPT


def _generate_offline_report(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Generates a high-quality deterministic defensive report without calling any external API."""
    if not findings:
        return {
            "model_used": "offline-kb",
            "fleet_risk_level": "CLEAN",
            "executive_summary": "All evaluated print infrastructure devices passed assessment baseline checks with zero confirmed critical or high vulnerabilities.",
            "prioritized_remediations": [],
            "cve_breakdowns": [],
            "report_markdown": "# Print Security Intelligence Report\n\n**Fleet Risk Level:** CLEAN\n\nNo actionable vulnerabilities detected across evaluated endpoints.",
        }

    severities = [f.get("severity", "INFO") for f in findings]
    if "CRITICAL" in severities:
        fleet_risk = "CRITICAL"
    elif "HIGH" in severities:
        fleet_risk = "HIGH"
    elif "MEDIUM" in severities:
        fleet_risk = "MEDIUM"
    else:
        fleet_risk = "LOW"

    # Prioritize remediations
    remediations = []
    cve_breakdowns = []
    seen_cves = set()

    for idx, f in enumerate(findings, start=1):
        cve = f.get("cve_id")
        if cve and cve not in seen_cves:
            seen_cves.add(cve)
            cve_breakdowns.append({
                "cve_id": cve,
                "cvss": f.get("cvss_score", 0.0),
                "exploitability_notes": f.get("description", ""),
                "affected_endpoints": [f.get("target", "Unknown")],
            })

        priority = 1 if f.get("severity") == "CRITICAL" else 2 if f.get("severity") == "HIGH" else 3
        remediations.append({
            "priority": priority,
            "target": f.get("target", "ALL"),
            "action": f.get("remediation", "Review and restrict protocol access."),
            "prerequisites": ["Ensure admin shell access or embedded web server credentials."],
            "verification": f"Re-run PRET assessment against target to confirm {f.get('title')} is resolved.",
            "rollback": "Re-enable previously disabled services if standard printing is impacted.",
        })

    # Build Markdown report
    md_lines = [
        f"# Fleet Print Security Intelligence Report",
        f"**Fleet Risk Posture:** `{fleet_risk}` | **Total Findings:** {len(findings)} | **Engine:** Offline Knowledge Base\n",
        f"## Executive Risk Summary",
        f"Security evaluation across registered print assets identified {len(findings)} finding(s). "
        f"Priority focus should be directed at {fleet_risk}-severity network exposures.\n",
        f"## Prioritized Action Runbook",
    ]

    for rem in remediations:
        md_lines.append(f"### [Priority {rem['priority']}] Target: `{rem['target']}`")
        md_lines.append(f"- **Action:** {rem['action']}")
        md_lines.append(f"- **Verification:** {rem['verification']}")
        md_lines.append("")

    return {
        "model_used": "offline-kb",
        "fleet_risk_level": fleet_risk,
        "executive_summary": f"Identified {len(findings)} finding(s) with an overall fleet risk of {fleet_risk}.",
        "prioritized_remediations": remediations,
        "cve_breakdowns": cve_breakdowns,
        "report_markdown": "\n".join(md_lines),
    }


def generate_intelligence_report(
    findings: list[dict[str, Any]],
    api_key: str | None = None,
    model: str = "sonar",
    timeout: int = 30,
) -> dict[str, Any]:
    """
    Main entrypoint for generating post-assessment intelligence reports.
    Pre-sanitizes all data with redact_sensitive_data before network transmission.
    Falls back to offline KB if no key is supplied or API fails.
    """
    sanitized_findings = redact_sensitive_data(findings)

    if not api_key or not api_key.strip():
        return _generate_offline_report(sanitized_findings)

    prompt = (
        f"Analyze these {len(sanitized_findings)} normalized findings from network printers and print servers:\n\n"
        f"{json.dumps(sanitized_findings, indent=2)}\n\n"
        "Generate a comprehensive defensive intelligence report formatted in Markdown."
    )

    try:
        resp = requests.post(
            "https://api.perplexity.ai/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key.strip()}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": _get_system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 2048,
            },
            timeout=timeout,
        )

        if resp.ok:
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            if content:
                offline = _generate_offline_report(sanitized_findings)
                offline["model_used"] = model
                offline["report_markdown"] = content
                return offline

    except Exception:
        # Fall back to offline deterministic report
        pass

    return _generate_offline_report(sanitized_findings)
