"""
Local Secret & Credential Redactor.
Pure-Python sanitizer that redacts passwords, SNMP strings, private keys,
and session tokens locally BEFORE data leaves the system.
See 05-SECURITY-ARCHITECTURE.md and PRET UI/UX Plan Phase 4.3.
"""
from __future__ import annotations

import re
from typing import Any

# Regex patterns for high-risk credentials and tokens
_PATTERNS = [
    # Private keys (PEM headers)
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", re.IGNORECASE), "[REDACTED_PRIVATE_KEY]"),
    # Passwords in PJL / PostScript / commands: e.g. password=XYZ, pwd=XYZ, @PJL DEFAULT PASSWORD=XYZ
    (re.compile(r"(password|passwd|pwd|secret|auth_token|token)\s*[:=]\s*['\"]?([^\s,;'\"&]+)['\"]?", re.IGNORECASE), r"\1=[REDACTED_SECRET]"),
    # Common PJL password commands
    (re.compile(r"(@PJL\s+DEFAULT\s+PASSWORD\s*=\s*)([^\r\n]+)", re.IGNORECASE), r"\1[REDACTED_PJL_PASSWORD]"),
    # Bearer tokens
    (re.compile(r"Bearer\s+[A-Za-z0-9\-_\.=]+", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    # SNMP community strings in output
    (re.compile(r"community\s*[:=]\s*['\"]?([^\s,;'\"&]+)['\"]?", re.IGNORECASE), "community=[REDACTED_COMMUNITY]"),
]


def redact_text(text: str) -> str:
    """Sanitizes a single string by masking sensitive patterns."""
    if not isinstance(text, str):
        return text
    sanitized = text
    for pattern, replacement in _PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def redact_sensitive_data(obj: Any) -> Any:
    """
    Recursively walks a dict, list, or string and redacts all known secrets.
    Does not mutate the original data structure.
    """
    if isinstance(obj, str):
        return redact_text(obj)
    elif isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            # Check key name for sensitive markers
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("password", "secret", "private_key", "credential", "token")):
                result[k] = "[REDACTED_FIELD]"
            else:
                result[k] = redact_sensitive_data(v)
        return result
    elif isinstance(obj, list):
        return [redact_sensitive_data(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(redact_sensitive_data(item) for item in obj)
    return obj
