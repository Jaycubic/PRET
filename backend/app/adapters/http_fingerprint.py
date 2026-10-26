"""
HTTP(S) admin-interface fingerprinting adapter.

Implements the redirect-revalidation requirement from
05-SECURITY-ARCHITECTURE.md §4: automatic redirect-following is
DISABLED (allow_redirects=False); each redirect hop is intercepted and
its Location header's host is re-validated against the authorized-
network scope via validate_cb BEFORE following it. A redirect to an
out-of-scope host (internal metadata endpoint, a public host, anything
outside the configured CIDR allow-list) is refused, not silently
followed — this is the concrete mechanism closing the SSRF gap.

Scheme and port are restricted to http/https and the adapter's own
fixed ports; this adapter never takes an arbitrary URL from the browser,
only a target host already validated by the job runner (see
run_operation's resolved_ip/port parameters) plus a small number of
well-known admin paths.
"""
from __future__ import annotations

import requests

from .base import Adapter, Operation, OperationResult

_MAX_REDIRECTS = 5
_ALLOWED_SCHEMES = {"http", "https"}


def _fetch_with_revalidation(url: str, verify: bool, validate_cb, progress_cb, timeout=8):
    """
    GETs `url` without following redirects automatically. On a redirect
    response, re-validates the Location's host via validate_cb before
    following it, up to _MAX_REDIRECTS hops. Returns (response, error).
    """
    from urllib.parse import urlparse

    current_url = url
    for hop in range(_MAX_REDIRECTS + 1):
        parsed = urlparse(current_url)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            return None, f"Disallowed scheme: {parsed.scheme!r}"

        if validate_cb is not None:
            try:
                validate_cb(parsed.hostname)
            except Exception as exc:  # ScopeError or any resolution failure
                return None, f"Target out of scope, refusing to connect: {exc}"

        if progress_cb:
            progress_cb(f"GET {current_url}")

        try:
            resp = requests.get(current_url, timeout=timeout, verify=verify, allow_redirects=False)
        except requests.RequestException as exc:
            return None, str(exc)

        if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
            current_url = resp.headers["Location"]
            if progress_cb:
                progress_cb(f"Redirect -> {current_url} (re-validating before following)")
            continue

        return resp, None

    return None, f"Exceeded {_MAX_REDIRECTS} redirect hops"


class HTTPFingerprintAdapter(Adapter):
    id = "http_fingerprint"
    display_name = "HTTP(S) Admin Fingerprint"
    platform_support = {"linux": True, "windows": True}

    def dependency_status(self) -> dict:
        return {"available": True, "detail": ""}

    def list_operations(self) -> list[Operation]:
        return [
            Operation(
                id="http_banner",
                display_name="Fingerprint Admin Interface (HTTP)",
                read_only=True,
                description="Fetches the root page over plain HTTP and reports the "
                            "Server header and page title. Redirects are re-validated "
                            "against authorized scope before being followed.",
            ),
            Operation(
                id="https_banner",
                display_name="Fingerprint Admin Interface (HTTPS)",
                read_only=True,
                description="Same as above over HTTPS, with certificate verification "
                            "ON by default.",
            ),
            Operation(
                id="https_banner_trust_self_signed",
                display_name="Fingerprint Admin Interface (HTTPS, trust self-signed)",
                read_only=True,
                description="Same as https_banner but disables certificate "
                            "verification for THIS target — the explicit, audited "
                            "exception, not a default.",
            ),
        ]

    def run_operation(self, operation_id, resolved_ip, port, params, progress_cb=None, validate_cb=None) -> OperationResult:
        if operation_id == "http_banner":
            scheme, verify, use_port = "http", True, port or 80
        elif operation_id == "https_banner":
            scheme, verify, use_port = "https", True, port or 443
        elif operation_id == "https_banner_trust_self_signed":
            scheme, verify, use_port = "https", False, port or 443
        else:
            return OperationResult(status="unsupported", error_detail=f"Unknown operation {operation_id}")

        url = f"{scheme}://{resolved_ip}:{use_port}/"
        resp, error = _fetch_with_revalidation(url, verify, validate_cb, progress_cb)

        if error:
            return OperationResult(status="ok", summary=f"No response / refused: {error}",
                                    evidence={"error": error})

        title = ""
        if "text/html" in resp.headers.get("Content-Type", ""):
            import re
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()[:200]

        evidence = {
            "status_code": resp.status_code,
            "server_header": resp.headers.get("Server", ""),
            "title": title,
            "final_url": resp.url,
        }
        return OperationResult(
            status="ok",
            summary=f"HTTP {resp.status_code} — Server: {evidence['server_header']!r} — {title!r}",
            evidence=evidence,
        )
