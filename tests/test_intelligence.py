"""
Unit tests for intelligence normalization, secret redaction,
and offline report synthesis.
"""
import pytest
from app.intelligence.redactor import redact_text, redact_sensitive_data
from app.intelligence.normalizer import normalize_device_results
from app.intelligence.client import generate_intelligence_report


def test_redactor_masks_passwords_and_tokens():
    raw_text = "Target credentials: password=supersecret123 and token='abc-9988-xyz'"
    sanitized = redact_text(raw_text)
    assert "supersecret123" not in sanitized
    assert "abc-9988-xyz" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized

    # Private key PEM test
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----"
    sanitized_pem = redact_text(pem)
    assert "MIIEowIBAAKCAQEA0" not in sanitized_pem
    assert "[REDACTED_PRIVATE_KEY]" in sanitized_pem


def test_redactor_recursive_dict():
    data = {
        "device_ip": "172.16.159.5",
        "admin_password": "PlaintextPassword",
        "nested": {
            "snmp_community": "community=public",
            "safe_field": "HP LaserJet Pro",
        },
    }
    redacted = redact_sensitive_data(data)
    assert redacted["admin_password"] == "[REDACTED_FIELD]"
    assert "PlaintextPassword" not in str(redacted)
    assert redacted["nested"]["safe_field"] == "HP LaserJet Pro"
    assert "community=[REDACTED_COMMUNITY]" in redacted["nested"]["snmp_community"]


def test_normalizer_negative_fixtures():
    # Failed jobs and empty results must produce ZERO findings
    failed_result = {
        "status": "error",
        "adapter_id": "cups_server",
        "evidence_json": {"chain_exploitable": True},
    }
    findings = normalize_device_results(1, "172.16.159.5", [failed_result])
    assert len(findings) == 0

    empty_result = {
        "status": "ok",
        "adapter_id": "pjl",
        "evidence_json": {},
    }
    findings_empty = normalize_device_results(1, "172.16.159.5", [empty_result])
    assert len(findings_empty) == 0


def test_normalizer_positive_matches():
    cups_result = {
        "status": "ok",
        "adapter_id": "cups_server",
        "evidence_json": {
            "chain_exploitable": True,
            "udp_631_exposed": True,
        },
    }
    findings = normalize_device_results(2, "172.16.159.10", [cups_result])
    assert len(findings) >= 1
    cve_ids = [f.get("cve_id") for f in findings]
    assert "CVE-2024-47176" in cve_ids
    assert findings[0]["severity"] == "CRITICAL"


def test_offline_intelligence_report():
    sample_findings = [
        {
            "id": "CUPS-1",
            "target": "172.16.159.10",
            "title": "CUPS Remote Code Execution Chain",
            "cve_id": "CVE-2024-47176",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "category": "RCE",
            "remediation": "Disable cups-browsed",
            "description": "UDP 631 packet parsing leads to code execution.",
        }
    ]
    report = generate_intelligence_report(sample_findings, api_key=None)
    assert report["model_used"] == "offline-kb"
    assert report["fleet_risk_level"] == "CRITICAL"
    assert len(report["prioritized_remediations"]) == 1
    assert "Disable cups-browsed" in report["prioritized_remediations"][0]["action"]
    assert "Fleet Print Security Intelligence Report" in report["report_markdown"]
