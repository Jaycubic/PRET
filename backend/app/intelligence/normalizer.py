"""
Deterministic Finding Normalizer.
Extracts structured vulnerability and weakness objects from Result.evidence_json
using local rules from vuln_mapping.json. Operates 100% offline.
See PRET UI/UX Plan Phase 4.2.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_MAPPING_FILE = Path(__file__).parent / "vuln_mapping.json"
_RULES_CACHE: list[dict[str, Any]] | None = None


def _load_rules() -> list[dict[str, Any]]:
    global _RULES_CACHE
    if _RULES_CACHE is None:
        if _MAPPING_FILE.exists():
            with open(_MAPPING_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                _RULES_CACHE = data.get("rules", [])
        else:
            _RULES_CACHE = []
    return _RULES_CACHE


def _get_nested(data: dict[str, Any], path: str) -> Any:
    """Traverses a dot-delimited path into a dict."""
    parts = path.split(".")
    curr = data
    for p in parts:
        if isinstance(curr, dict) and p in curr:
            curr = curr[p]
        else:
            return None
    return curr


def _matches_condition(condition: dict[str, Any], evidence: dict[str, Any]) -> bool:
    """Evaluates whether an evidence dictionary matches a rule condition."""
    if not evidence or not isinstance(evidence, dict):
        return False

    if "or" in condition:
        return any(_matches_condition(c, evidence) for c in condition["or"])
    if "and" in condition:
        return all(_matches_condition(c, evidence) for c in condition["and"])

    field = condition.get("field")
    if not field:
        return False

    val = _get_nested(evidence, field)
    if "equals" in condition:
        return val == condition["equals"]
    if "not_null" in condition:
        return val is not None
    if "contains" in condition:
        return isinstance(val, (str, list)) and condition["contains"] in val

    return False


def normalize_device_results(
    device_id: int,
    target_name: str,
    results: list[dict[str, Any] | Any],
) -> list[dict[str, Any]]:
    """
    Evaluates evidence from completed assessment results for a device and extracts
    deduplicated normalized findings.
    Failed/errored jobs and empty outputs produce NO findings (negative fixture requirement).
    """
    rules = _load_rules()
    findings: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()

    for r in results:
        # Convert SQLAlchemy Result or dict
        status = getattr(r, "status", None) or (r.get("status") if isinstance(r, dict) else None)
        # Errored, blocked, or failed runs must not be normalized into findings
        if status not in ("ok", "succeeded"):
            continue

        adapter_id = getattr(r, "adapter_id", None) or (r.get("adapter_id") if isinstance(r, dict) else "")
        evidence = getattr(r, "evidence_json", None) or (r.get("evidence_json") if isinstance(r, dict) else {})
        if not evidence or not isinstance(evidence, dict):
            continue

        for rule in rules:
            rule_id = rule["id"]
            if rule_id in seen_rule_ids:
                continue

            # Match adapter ID if specified
            if rule.get("adapter_id") and rule["adapter_id"] != adapter_id:
                continue

            cond = rule.get("condition", {})
            if _matches_condition(cond, evidence):
                seen_rule_ids.add(rule_id)
                findings.append({
                    "id": f"{rule_id}-{device_id}",
                    "rule_id": rule_id,
                    "device_id": device_id,
                    "target": target_name,
                    "title": rule["title"],
                    "cve_id": rule.get("cve_id"),
                    "cwe_id": rule.get("cwe_id"),
                    "cvss_score": rule.get("cvss_score", 0.0),
                    "severity": rule.get("severity", "INFO"),
                    "category": rule.get("category", "General"),
                    "description": rule.get("description", ""),
                    "remediation": rule.get("remediation", ""),
                    "evidence_snippet": f"Triggered on {adapter_id} evidence: {json.dumps(evidence)[:200]}",
                })

    return findings
