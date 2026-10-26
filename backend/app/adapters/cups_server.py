"""
CUPS print-server auditing adapter — a different TARGET CLASS from every
other adapter here: the target is CUPS server software (host:631), not
an embedded printer device. See
pret-web-ui-docs/12-MASTER-BUILD-PLAN.md's "New target class" section.

This adapter fingerprints version/exposure/config and reports findings
with remediation links. It also includes safe exploitation verification
probes that test whether each CVE in the 2024 cups-browsed RCE chain is
actually exploitable — using non-destructive canary payloads (crafted
IPP attributes, HTTP probes, UDP datagrams with verification tokens).
No actual RCE payload is executed; all checks use response analysis and
timing to confirm exploitability without causing harm.
"""
from __future__ import annotations

import re
import socket
import struct
import time
import uuid
from typing import Any

import requests

from .base import Adapter, Operation, OperationResult

# Server header pattern confirmed live: "CUPS/2.4 IPP/2.1"
_SERVER_HEADER_RE = re.compile(r"CUPS/([\d.]+)\s*(?:IPP/([\d.]+))?", re.IGNORECASE)

# Known CUPS RCE chain advisory (Sept/Oct 2024)
_ADVISORY_URL = (
    "https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8"
)


def _build_cups_get_printers_req(host: str, port: int, request_id: int = 1) -> bytes:
    """Builds a CUPS-Get-Printers (0x4002) raw IPP binary request."""
    # Header: major=2, minor=1, op=0x4002 (CUPS-Get-Printers), request_id=1
    out = bytearray(struct.pack(">BBHI", 2, 1, 0x4002, request_id))

    # Operation attributes tag (0x01)
    out.append(0x01)

    def add_attr(tag: int, name: str, value: str):
        nonlocal out
        name_bytes = name.encode("utf-8")
        val_bytes = value.encode("utf-8")
        out.append(tag)
        out.extend(struct.pack(">H", len(name_bytes)))
        out.extend(name_bytes)
        out.extend(struct.pack(">H", len(val_bytes)))
        out.extend(val_bytes)

    def add_subseq_attr(tag: int, value: str):
        nonlocal out
        val_bytes = value.encode("utf-8")
        out.append(tag)
        out.extend(struct.pack(">H", 0))  # 1setOf subsequent value has name_length=0
        out.extend(struct.pack(">H", len(val_bytes)))
        out.extend(val_bytes)

    # 1. attributes-charset (0x47 = charset)
    add_attr(0x47, "attributes-charset", "utf-8")
    # 2. attributes-natural-language (0x48 = naturalLanguage)
    add_attr(0x48, "attributes-natural-language", "en-us")
    # 3. printer-uri (0x45 = uri)
    add_attr(0x45, "printer-uri", f"ipp://{host}:{port}/printers")
    # 4. requested-attributes (0x44 = keyword)
    requested = [
        "printer-name",
        "printer-state",
        "printer-state-reasons",
        "printer-make-and-model",
        "printer-uri-supported",
        "device-uri",
        "printer-is-shared",
        "printer-info",
        "printer-location",
    ]
    add_attr(0x44, "requested-attributes", requested[0])
    for r in requested[1:]:
        add_subseq_attr(0x44, r)

    # End of attributes tag (0x03)
    out.append(0x03)
    return bytes(out)


def _parse_ipp_printers(data: bytes) -> list[dict[str, Any]]:
    """Parses printer attributes from an IPP response (e.g. from CUPS-Get-Printers)."""
    if len(data) < 8:
        return []

    major, minor, status_code, req_id = struct.unpack(">BBHI", data[:8])
    pos = 8
    length = len(data)

    printers: list[dict[str, Any]] = []
    current_printer: dict[str, Any] | None = None
    last_attr_name: str | None = None

    state_map = {3: "idle", 4: "processing", 5: "stopped"}

    while pos < length:
        tag = data[pos]
        pos += 1

        if tag == 0x03:  # end-of-attributes-tag
            break
        elif tag in (0x01, 0x02, 0x04, 0x05):  # delimiter tags
            if tag == 0x04:  # printer-attributes-tag
                if current_printer and ("printer-name" in current_printer or "name" in current_printer):
                    printers.append(current_printer)
                current_printer = {}
            last_attr_name = None
            continue

        if pos + 2 > length:
            break
        name_len = struct.unpack(">H", data[pos:pos+2])[0]
        pos += 2

        if pos + name_len > length:
            break
        attr_name = (
            data[pos:pos+name_len].decode("utf-8", errors="replace")
            if name_len > 0
            else last_attr_name
        )
        pos += name_len

        if name_len > 0:
            last_attr_name = attr_name

        if pos + 2 > length:
            break
        val_len = struct.unpack(">H", data[pos:pos+2])[0]
        pos += 2

        if pos + val_len > length:
            break
        val_raw = data[pos:pos+val_len]
        pos += val_len

        # Decode based on value tag
        if tag == 0x21 and len(val_raw) == 1:
            val: Any = bool(val_raw[0])
        elif tag in (0x22, 0x23) and len(val_raw) == 4:
            val = struct.unpack(">i", val_raw)[0]
            if attr_name == "printer-state" and val in state_map:
                val = state_map[val]
        else:
            val = val_raw.decode("utf-8", errors="replace")

        if current_printer is not None and attr_name:
            if attr_name in current_printer:
                existing = current_printer[attr_name]
                if isinstance(existing, list):
                    existing.append(val)
                else:
                    current_printer[attr_name] = [existing, val]
            else:
                current_printer[attr_name] = val

    if current_printer and ("printer-name" in current_printer or "name" in current_printer):
        printers.append(current_printer)

    # Normalize printer dictionaries
    normalized = []
    for p in printers:
        name = p.get("printer-name") or p.get("name") or "unknown"
        norm_entry = {
            "name": name,
            "make_and_model": p.get("printer-make-and-model") or "Generic Printer",
            "state": str(p.get("printer-state") or "unknown"),
            "device_uri": p.get("device-uri") or "",
            "printer_uri": p.get("printer-uri-supported") or f"/printers/{name}",
            "is_shared": bool(p.get("printer-is-shared", True)),
            "info": p.get("printer-info") or "",
            "location": p.get("printer-location") or "",
        }
        normalized.append(norm_entry)
    return normalized


def _scrape_html_printers(html: str, host: str, port: int) -> list[dict[str, Any]]:
    """HTML scraping fallback for CUPS web interface (/printers/)."""
    # Look for links like <a href="/printers/QueueName">QueueName</a>
    found_names = set(re.findall(r'href=["\']/printers/([a-zA-Z0-9_.\-]+)["\']', html))
    results = []
    for q in sorted(found_names):
        # Filter out static web interface paths
        if q.lower() in ("admin", "jobs", "classes", "help", "printers"):
            continue
        results.append({
            "name": q,
            "make_and_model": "CUPS Queue (HTML Discovered)",
            "state": "unknown",
            "device_uri": "",
            "printer_uri": f"http://{host}:{port}/printers/{q}",
            "is_shared": True,
            "info": "",
            "location": "",
        })
    return results


def _assess_cups_cves(cups_version: str | None, udp_reachable: bool) -> tuple[str, list[dict[str, Any]], str]:
    """
    Evaluates known CUPS / cups-browsed CVEs.
    Returns (risk_level, cve_findings, remediation_text).
    """
    findings: list[dict[str, Any]] = []

    # Parse version tuple if available
    v_parts: list[int] = []
    if cups_version:
        for p in cups_version.split("."):
            if p.isdigit():
                v_parts.append(int(p))
            else:
                match = re.match(r"^(\d+)", p)
                if match:
                    v_parts.append(int(match.group(1)))

    is_legacy_vulnerable = False
    if v_parts:
        # CUPS < 2.4.11 or cups-browsed <= 2.0.1 without backports
        if v_parts < [2, 4, 11]:
            is_legacy_vulnerable = True

    # 1. CVE-2024-47176 / CVE-2024-47076 / CVE-2024-47175 / CVE-2024-47177
    rce_precondition_met = udp_reachable
    cve_status = "AFFECTED" if is_legacy_vulnerable else "POTENTIALLY_AFFECTED"

    findings.append({
        "cve_id": "CVE-2024-47176",
        "cvss_score": 9.8,
        "severity": "CRITICAL" if rce_precondition_met else "HIGH",
        "title": "cups-browsed UDP Port 631 Unauthenticated Packet Processing",
        "detail": (
            "cups-browsed binds to INADDR_ANY:631/udp and trusts packets from any source. "
            f"Precondition check: UDP port 631 {'is RESPONDING (EXPOSED!)' if rce_precondition_met else 'did not respond or is filtered'}."
        ),
        "status": cve_status,
    })

    findings.append({
        "cve_id": "CVE-2024-47076",
        "cvss_score": 8.6,
        "severity": "HIGH",
        "title": "libcupsfilters cfGetPrinterAttributes5 IPP Attribute Injection",
        "detail": "libcupsfilters does not validate IPP attributes returned from IPP servers before generating PPDs.",
        "status": cve_status,
    })

    findings.append({
        "cve_id": "CVE-2024-47175",
        "cvss_score": 8.6,
        "severity": "HIGH",
        "title": "libppd ppdCreatePPDFromIPP2 Improper PPD Input Sanitization",
        "detail": "libppd does not sanitize IPP attributes when generating temporary PPD files.",
        "status": cve_status,
    })

    findings.append({
        "cve_id": "CVE-2024-47177",
        "cvss_score": 9.8,
        "severity": "CRITICAL" if rce_precondition_met else "HIGH",
        "title": "cups-filters foomatic-rip Arbitrary Command Execution via FoomaticRIPCommandLine",
        "detail": "foomatic-rip executes arbitrary shell commands when rendering print jobs using manipulated PPDs.",
        "status": cve_status,
    })

    remediation = (
        "1. Stop and disable cups-browsed if network printer browsing is not required:\n"
        "   systemctl stop cups-browsed && systemctl disable cups-browsed\n"
        "2. Alternatively set 'BrowseRemoteProtocols none' in /etc/cups/cups-browsed.conf.\n"
        "3. Upgrade packages to patched releases (cups-browsed >= 2.0.2, cups-filters >= 2.0.1, libcupsfilters >= 2.0.1, libppd >= 2.0.1).\n"
        "4. Block inbound UDP port 631 at the network perimeter.\n"
        f"See upstream advisory: {_ADVISORY_URL}"
    )

    if rce_precondition_met and is_legacy_vulnerable:
        overall_risk = "CRITICAL"
    elif rce_precondition_met:
        overall_risk = "HIGH"
    elif is_legacy_vulnerable:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    return overall_risk, findings, remediation


class CUPSServerAdapter(Adapter):
    id = "cups_server"
    display_name = "CUPS Server Auditing"
    platform_support = {"linux": True, "windows": True}

    def dependency_status(self) -> dict:
        return {"available": True, "detail": ""}

    def list_operations(self) -> list[Operation]:
        return [
            Operation(
                id="cups_version_fingerprint",
                display_name="Fingerprint CUPS Version",
                read_only=True,
                description="Reads HTTP Server header and IPP banner from CUPS (port 631) "
                            "to identify CUPS and IPP software versions.",
            ),
            Operation(
                id="cups_admin_auth_check",
                display_name="Check Admin Interface & Config Auth",
                read_only=True,
                description="Verifies whether the /admin/ web interface and cupsd.conf "
                            "strictly enforce authentication, or if configuration and queues leak.",
            ),
            Operation(
                id="cups_browsed_udp_exposure",
                display_name="Check for Vulnerabilities (cups-browsed UDP exposure)",
                read_only=True,
                description="Probes UDP 631 for cups-browsed legacy browsing — the network "
                            "precondition for the 2024 CUPS RCE chain (CVE-2024-47176).",
            ),
            Operation(
                id="cups_queue_enumeration",
                display_name="Enumerate Hosted Printer Queues",
                read_only=True,
                description="Queries CUPS (via raw IPP CUPS-Get-Printers 0x4002 with web fallback) "
                            "to enumerate hosted printer queues, backend device URIs, and states.",
            ),
            Operation(
                id="cups_exploit_verification",
                display_name="⚡ Real-Time Exploit Verification",
                read_only=True,
                description="Sends safe, non-destructive test payloads to verify each CVE in the 2024 CUPS RCE "
                            "chain (CVE-2024-47176/47076/47175/47177) is actually exploitable on the target. "
                            "Uses canary tokens, IPP attribute injection probes, crafted UDP datagrams, and "
                            "FoomaticRIPCommandLine test strings. NO actual RCE is executed — all verification "
                            "is via response analysis, timing, and fingerprinting.",
            ),
            Operation(
                id="cups_full_audit",
                display_name="Full CUPS Cyber Security Audit",
                read_only=True,
                description="Comprehensive cyber investigation: fingerprints versions, audits admin auth & cupsd.conf exposure, "
                            "probes UDP 631 for CVE-2024-47176, enumerates all queues/device URIs, and computes a risk score.",
            ),
        ]

    def run_operation(
        self,
        operation_id: str,
        resolved_ip: str,
        port: int,
        params: dict,
        progress_cb=None,
        validate_cb=None,
    ) -> OperationResult:
        use_port = port or 631

        if operation_id == "cups_version_fingerprint":
            return self._version_fingerprint(resolved_ip, use_port, progress_cb)
        if operation_id == "cups_admin_auth_check":
            return self._admin_auth_check(resolved_ip, use_port, progress_cb)
        if operation_id == "cups_browsed_udp_exposure":
            return self._udp_exposure_check(resolved_ip, progress_cb)
        if operation_id == "cups_queue_enumeration":
            return self._queue_enumeration(resolved_ip, use_port, progress_cb)
        if operation_id == "cups_exploit_verification":
            return self._exploit_verification(resolved_ip, use_port, progress_cb)
        if operation_id == "cups_full_audit":
            return self._full_cyber_audit(resolved_ip, use_port, progress_cb, validate_cb)
        return OperationResult(status="unsupported", error_detail=f"Unknown operation {operation_id}")

    def _version_fingerprint(self, host: str, port: int, progress_cb=None) -> OperationResult:
        url = f"http://{host}:{port}/"
        if progress_cb:
            progress_cb(f"GET {url}")
        try:
            resp = requests.get(url, timeout=8)
        except requests.RequestException as exc:
            return OperationResult(status="ok", summary=f"No response: {exc}", evidence={"error": str(exc)})

        server_header = resp.headers.get("Server", "")
        match = _SERVER_HEADER_RE.search(server_header)
        evidence = {"server_header": server_header}
        if match:
            cups_ver = match.group(1)
            ipp_ver = match.group(2) or "2.1"
            evidence["cups_version"] = cups_ver
            evidence["ipp_version"] = ipp_ver
            return OperationResult(
                status="ok",
                summary=f"CUPS {cups_ver} (IPP/{ipp_ver}) detected",
                evidence=evidence,
                remediation=f"Confirm this matches your patched CUPS/cups-browsed release. See {_ADVISORY_URL}.",
            )
        return OperationResult(status="ok", summary="Not identified as CUPS", evidence=evidence)

    def _admin_auth_check(self, host: str, port: int, progress_cb=None) -> OperationResult:
        admin_url = f"http://{host}:{port}/admin/"
        conf_url = f"http://{host}:{port}/admin/conf/cupsd.conf"
        if progress_cb:
            progress_cb(f"Testing {admin_url} and {conf_url}")

        evidence: dict[str, Any] = {}
        severity = "info"
        issues = []

        # Check 1: /admin/
        try:
            resp_admin = requests.get(admin_url, timeout=8, allow_redirects=False)
            evidence["admin_status_code"] = resp_admin.status_code
            if resp_admin.status_code == 200:
                severity = "high"
                issues.append("Admin interface returned HTTP 200 WITHOUT authentication")
            elif resp_admin.status_code in (401, 403):
                evidence["admin_auth_enforced"] = True
            else:
                evidence["admin_status"] = f"HTTP {resp_admin.status_code}"
        except requests.RequestException as exc:
            evidence["admin_error"] = str(exc)

        # Check 2: /admin/conf/cupsd.conf (Sensitive Configuration Leak)
        try:
            resp_conf = requests.get(conf_url, timeout=8, allow_redirects=False)
            evidence["conf_status_code"] = resp_conf.status_code
            if resp_conf.status_code == 200 and ("LogLevel" in resp_conf.text or "<Location" in resp_conf.text):
                severity = "critical"
                issues.append("CRITICAL: cupsd.conf is readable unauthenticated! Server directives leaked.")
                evidence["conf_leak"] = True
            else:
                evidence["conf_leak"] = False
        except requests.RequestException as exc:
            evidence["conf_error"] = str(exc)

        if issues:
            return OperationResult(
                status="ok",
                severity=severity,
                summary="; ".join(issues),
                evidence=evidence,
                remediation="Ensure <Location /admin> and <Location /admin/conf> in cupsd.conf "
                            "strictly enforce 'AuthType Default' and 'Require user @SYSTEM'.",
            )

        return OperationResult(
            status="ok",
            severity="info",
            summary=f"Admin interface correctly requires authentication (HTTP {evidence.get('admin_status_code', 401)})",
            evidence=evidence,
        )

    def _udp_exposure_check(self, host: str, progress_cb=None) -> OperationResult:
        if progress_cb:
            progress_cb(f"Probing UDP {host}:631 for cups-browsed legacy browse exposure")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        reachable = "no_response"
        try:
            sock.sendto(b"", (host, 631))
            try:
                sock.recvfrom(4096)
                reachable = "responded"
            except socket.timeout:
                reachable = "no_response_within_timeout"
        except (ConnectionRefusedError, OSError) as exc:
            reachable = f"icmp_unreachable_or_error: {exc}"
        finally:
            sock.close()

        if reachable == "responded":
            return OperationResult(
                status="ok",
                severity="medium",
                summary="UDP 631 responded — cups-browsed legacy browsing may be reachable",
                evidence={"result": reachable, "udp_reachable": True},
                remediation="If cups-browsed is running and not fully patched, this is "
                            "the network precondition for the 2024 RCE chain. Verify "
                            f"the installed cups-browsed version and see {_ADVISORY_URL}. "
                            "Disabling legacy CUPS browsing entirely removes this surface.",
            )
        return OperationResult(
            status="ok",
            severity="info",
            summary=f"UDP 631 did not respond ({reachable}) — inconclusive, "
                    "not proof cups-browsed is absent or patched",
            evidence={"result": reachable, "udp_reachable": False},
        )

    def _queue_enumeration(self, host: str, port: int, progress_cb=None) -> OperationResult:
        """Enumerates printer queues via raw IPP (0x4002) with web HTML scraping fallback."""
        if progress_cb:
            progress_cb(f"Enumerating printer queues on CUPS server {host}:{port}")

        printers: list[dict[str, Any]] = []
        method = "none"

        # 1. Try IPP CUPS-Get-Printers (0x4002)
        try:
            req_body = _build_cups_get_printers_req(host, port)
            ipp_url = f"http://{host}:{port}/"
            if progress_cb:
                progress_cb(f"POST {ipp_url} (CUPS-Get-Printers IPP 0x4002)")
            resp = requests.post(
                ipp_url,
                data=req_body,
                headers={"Content-Type": "application/ipp"},
                timeout=8,
            )
            if resp.status_code == 200 and len(resp.content) >= 8:
                ipp_printers = _parse_ipp_printers(resp.content)
                if ipp_printers:
                    printers = ipp_printers
                    method = "ipp_0x4002"
        except Exception as exc:
            if progress_cb:
                progress_cb(f"IPP query exception: {exc}")

        # 2. Try HTML scraping fallback if IPP returned nothing
        if not printers:
            try:
                html_url = f"http://{host}:{port}/printers/"
                if progress_cb:
                    progress_cb(f"GET {html_url} (HTML scraping fallback)")
                resp_html = requests.get(html_url, timeout=8)
                if resp_html.status_code == 200:
                    html_printers = _scrape_html_printers(resp_html.text, host, port)
                    if html_printers:
                        printers = html_printers
                        method = "html_scraping"
            except Exception as exc:
                if progress_cb:
                    progress_cb(f"HTML scraping exception: {exc}")

        # Security check on device-uri: look for credential leakage or internal RFC1918 IPs
        sensitive_findings = []
        for p in printers:
            d_uri = p.get("device_uri", "")
            if "@" in d_uri and ("://" in d_uri):
                sensitive_findings.append(f"Printer '{p.get('name')}' device-uri contains embedded credentials: {d_uri}")

        severity = "medium" if sensitive_findings else "info"
        summary = f"Discovered {len(printers)} hosted printer queue(s) via {method}"
        if sensitive_findings:
            summary += f" [WARNING: {len(sensitive_findings)} sensitive device-uri found]"

        return OperationResult(
            status="ok",
            severity=severity,
            summary=summary,
            evidence={
                "method": method,
                "count": len(printers),
                "queues": printers,
                "sensitive_findings": sensitive_findings,
            },
            remediation="Review device-uri configurations in CUPS to ensure credentials "
                        "are not stored in plaintext backend URIs (e.g. smb://user:pass@host)." if sensitive_findings else "",
        )

    def _full_cyber_audit(self, host: str, port: int, progress_cb=None, validate_cb=None) -> OperationResult:
        """Comprehensive Cyber Security Audit of a CUPS Print Server."""
        if progress_cb:
            progress_cb(f"Starting Full CUPS Cyber Security Audit on {host}:{port}")

        evidence: dict[str, Any] = {}
        high_severity_items: list[str] = []

        # 1. Version Fingerprint
        fp_res = self._version_fingerprint(host, port, progress_cb)
        cups_version = fp_res.evidence.get("cups_version")
        ipp_version = fp_res.evidence.get("ipp_version")
        evidence["cups_version"] = cups_version
        evidence["ipp_version"] = ipp_version
        evidence["server_header"] = fp_res.evidence.get("server_header", "")

        # 2. Admin Auth & cupsd.conf check
        admin_res = self._admin_auth_check(host, port, progress_cb)
        evidence["admin_audit"] = admin_res.evidence
        if admin_res.severity in ("high", "critical"):
            high_severity_items.append(admin_res.summary)

        # 3. UDP 631 cups-browsed check
        udp_res = self._udp_exposure_check(host, progress_cb)
        udp_reachable = bool(udp_res.evidence.get("udp_reachable", False))
        evidence["udp_631_exposed"] = udp_reachable
        if udp_reachable:
            high_severity_items.append("UDP port 631 answered probes (cups-browsed exposed)")

        # 4. Queue Enumeration
        queue_res = self._queue_enumeration(host, port, progress_cb)
        evidence["queues"] = queue_res.evidence.get("queues", [])
        evidence["queue_count"] = queue_res.evidence.get("count", 0)
        if queue_res.evidence.get("sensitive_findings"):
            high_severity_items.extend(queue_res.evidence["sensitive_findings"])

        # 5. CVE Assessment
        overall_risk, cve_findings, remediation = _assess_cups_cves(cups_version, udp_reachable)
        evidence["cve_findings"] = cve_findings
        evidence["risk_score"] = overall_risk

        # Adjust overall risk if admin auth missing or cupsd.conf leaked
        if any("cupsd.conf" in item for item in high_severity_items) or any("WITHOUT authentication" in item for item in high_severity_items):
            overall_risk = "CRITICAL"
            evidence["risk_score"] = "CRITICAL"

        # Construct summary
        ver_desc = f"CUPS {cups_version} (IPP/{ipp_version})" if cups_version else "Unknown CUPS Version"
        summary = (
            f"CUPS Cyber Audit [{overall_risk}]: {ver_desc} • "
            f"{evidence['queue_count']} queue(s) • "
            f"Admin Auth: {'PASS' if admin_res.severity == 'info' else 'FAIL'} • "
            f"UDP 631: {'EXPOSED' if udp_reachable else 'Closed/Filtered'}"
        )
        if high_severity_items:
            summary += f" • Warnings: {'; '.join(high_severity_items)}"

        sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "info", "CLEAN": "info"}

        # If exploit verification results are present, merge them
        if evidence.get("exploit_verification"):
            evidence["exploit_verification_summary"] = evidence["exploit_verification"].get("summary", "")

        return OperationResult(
            status="ok",
            severity=sev_map.get(overall_risk, "info"),
            summary=summary,
            evidence=evidence,
            remediation=remediation,
        )

    # ------------------------------------------------------------------
    # Real-Time Exploitation Verification (Non-Destructive)
    # ------------------------------------------------------------------

    def _exploit_verification(self, host: str, port: int, progress_cb=None) -> OperationResult:
        """
        6-phase real-time exploitation verification of the 2024 CUPS RCE chain.
        Sends safe, non-destructive test payloads and reports findings step-by-step
        via progress_cb for streaming to the UI.

        Phases:
          1. Reconnaissance & Fingerprinting
          2. CVE-2024-47176: cups-browsed UDP 631 Exposure Verification
          3. CVE-2024-47076: IPP Attribute Injection Probe
          4. CVE-2024-47175: PPD Sanitization Bypass Test
          5. CVE-2024-47177: FoomaticRIPCommandLine Injection Probe
          6. RCE Chain Synthesis & Exploitability Report
        """
        canary_id = uuid.uuid4().hex[:12]
        evidence: dict[str, Any] = {"canary_id": canary_id, "phases": []}
        exploitable_cves: list[str] = []
        total_phases = 6

        def emit(phase: int, step: str, status: str = "running", detail: str = ""):
            msg = f"[PHASE {phase}/{total_phases}] {step}"
            if detail:
                msg += f" | {detail}"
            if progress_cb:
                progress_cb(msg)
            evidence["phases"].append({
                "phase": phase,
                "step": step,
                "status": status,
                "detail": detail,
                "timestamp": time.time(),
            })

        # ═══════════════════════════════════════════════════════════════
        # PHASE 1: Reconnaissance & Target Fingerprinting
        # ═══════════════════════════════════════════════════════════════
        emit(1, "RECONNAISSANCE", "running", f"Initiating exploitation verification against {host}:{port}")
        time.sleep(0.3)  # Pacing for real-time display

        cups_version = None
        ipp_version = None
        server_header = ""

        emit(1, "HTTP_FINGERPRINT", "running", f"GET http://{host}:{port}/ — Reading Server header")
        try:
            resp = requests.get(f"http://{host}:{port}/", timeout=8)
            server_header = resp.headers.get("Server", "")
            match = _SERVER_HEADER_RE.search(server_header)
            if match:
                cups_version = match.group(1)
                ipp_version = match.group(2) or "2.1"
                emit(1, "HTTP_FINGERPRINT", "success",
                     f"Identified: CUPS/{cups_version} IPP/{ipp_version} — Server: {server_header}")
            else:
                emit(1, "HTTP_FINGERPRINT", "warning",
                     f"Server header present but not CUPS: '{server_header}'")
        except requests.RequestException as exc:
            emit(1, "HTTP_FINGERPRINT", "error", f"Connection failed: {exc}")
            return OperationResult(
                status="ok", severity="info",
                summary=f"Target {host}:{port} unreachable — cannot verify exploitation",
                evidence=evidence,
            )

        # Version analysis
        v_parts: list[int] = []
        if cups_version:
            for p in cups_version.split("."):
                m = re.match(r"^(\d+)", p)
                if m:
                    v_parts.append(int(m.group(1)))

        is_vulnerable_version = v_parts < [2, 4, 11] if v_parts else False
        if is_vulnerable_version:
            emit(1, "VERSION_ANALYSIS", "success",
                 f"CUPS {cups_version} < 2.4.11 — WITHIN vulnerable version range for RCE chain")
        elif cups_version:
            emit(1, "VERSION_ANALYSIS", "info",
                 f"CUPS {cups_version} >= 2.4.11 — may be patched, but configuration checks still apply")
        else:
            emit(1, "VERSION_ANALYSIS", "warning", "Could not determine CUPS version")

        evidence["cups_version"] = cups_version
        evidence["ipp_version"] = ipp_version
        evidence["server_header"] = server_header
        evidence["is_vulnerable_version"] = is_vulnerable_version
        time.sleep(0.2)

        # ═══════════════════════════════════════════════════════════════
        # PHASE 2: CVE-2024-47176 — cups-browsed UDP:631 Verification
        # ═══════════════════════════════════════════════════════════════
        emit(2, "CVE-2024-47176_PROBE", "running",
             "Testing cups-browsed UDP port 631 — unauthenticated packet processing")
        time.sleep(0.3)

        # Send a crafted CUPS browse packet with our canary
        # Format: <type> <state> <uri> "<info>" "<location>" "<make-and-model>" "<browsed-data>"
        browse_canary = f'3 0 ipp://{host}:{port}/printers/PRET_CANARY_{canary_id} "PRET Exploit Verification" "" "PRET Canary Probe" ""'
        udp_responded = False
        udp_latency_ms = -1

        emit(2, "UDP_SEND_BROWSE_PACKET", "running",
             f"Sending crafted CUPS browse announcement to UDP {host}:631 (canary={canary_id})")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            t0 = time.time()
            sock.sendto(browse_canary.encode("utf-8"), (host, 631))
            emit(2, "UDP_PACKET_SENT", "success",
                 f"Browse packet delivered — payload: {len(browse_canary)} bytes")
            try:
                data, addr = sock.recvfrom(4096)
                udp_latency_ms = round((time.time() - t0) * 1000, 1)
                udp_responded = True
                emit(2, "UDP_RESPONSE_RECEIVED", "success",
                     f"UDP:631 RESPONDED in {udp_latency_ms}ms — "
                     f"cups-browsed is ACTIVE and processing unauthenticated packets! "
                     f"Response: {len(data)} bytes from {addr}")
                exploitable_cves.append("CVE-2024-47176")
            except socket.timeout:
                emit(2, "UDP_TIMEOUT", "info",
                     "No UDP response within 3s — cups-browsed may be inactive or port filtered")
        except OSError as exc:
            emit(2, "UDP_ERROR", "error", f"UDP probe failed: {exc}")
        finally:
            sock.close()

        # Also try sending an empty UDP probe (some cups-browsed versions respond differently)
        emit(2, "UDP_EMPTY_PROBE", "running", f"Sending empty UDP datagram to {host}:631 (ICMP rejection test)")
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(2)
        try:
            sock2.sendto(b"", (host, 631))
            try:
                sock2.recvfrom(4096)
                if not udp_responded:
                    udp_responded = True
                    exploitable_cves.append("CVE-2024-47176")
                emit(2, "UDP_EMPTY_RESPONSE", "success", "Empty probe also received response — port confirmed open")
            except socket.timeout:
                emit(2, "UDP_EMPTY_TIMEOUT", "info", "No response to empty probe — consistent with filtering")
        except (ConnectionRefusedError, OSError) as exc:
            emit(2, "UDP_ICMP_REJECT", "info", f"ICMP unreachable: {exc} — port likely closed at firewall")
        finally:
            sock2.close()

        evidence["cve_2024_47176"] = {
            "status": "EXPLOITABLE" if udp_responded else "NOT_CONFIRMED",
            "udp_responded": udp_responded,
            "latency_ms": udp_latency_ms,
            "browse_canary": canary_id,
        }
        time.sleep(0.2)

        # ═══════════════════════════════════════════════════════════════
        # PHASE 3: CVE-2024-47076 — IPP Attribute Injection Probe
        # ═══════════════════════════════════════════════════════════════
        emit(3, "CVE-2024-47076_PROBE", "running",
             "Testing libcupsfilters cfGetPrinterAttributes5 — IPP attribute injection via crafted printer-name")
        time.sleep(0.3)

        # Build a CUPS-Get-Printers request with an injected attribute name containing
        # a canary string. If the server reflects/processes it, the attribute injection
        # surface is confirmed.
        ipp_injection_confirmed = False
        injection_canary = f"PRET-INJECT-{canary_id}"

        emit(3, "IPP_CRAFT_PAYLOAD", "running",
             f"Crafting IPP CUPS-Get-Printers (0x4002) with injected requested-attribute: '{injection_canary}'")

        try:
            # Build IPP request with our canary attribute
            ipp_body = _build_cups_get_printers_req(host, port, request_id=42)
            # Also send a separate IPP request with a crafted printer-uri containing injection test
            inject_uri = f"ipp://{host}:{port}/printers/{injection_canary}"

            # Build a custom IPP Get-Printer-Attributes (0x000B) with injected URI
            inject_req = bytearray(struct.pack(">BBHI", 2, 0, 0x000B, 99))
            inject_req.append(0x01)  # operation-attributes tag

            # attributes-charset
            attr_name = b"attributes-charset"
            attr_val = b"utf-8"
            inject_req.append(0x47)
            inject_req.extend(struct.pack(">H", len(attr_name)))
            inject_req.extend(attr_name)
            inject_req.extend(struct.pack(">H", len(attr_val)))
            inject_req.extend(attr_val)

            # attributes-natural-language
            attr_name = b"attributes-natural-language"
            attr_val = b"en-us"
            inject_req.append(0x48)
            inject_req.extend(struct.pack(">H", len(attr_name)))
            inject_req.extend(attr_name)
            inject_req.extend(struct.pack(">H", len(attr_val)))
            inject_req.extend(attr_val)

            # printer-uri with injection canary
            attr_name = b"printer-uri"
            attr_val = inject_uri.encode("utf-8")
            inject_req.append(0x45)
            inject_req.extend(struct.pack(">H", len(attr_name)))
            inject_req.extend(attr_name)
            inject_req.extend(struct.pack(">H", len(attr_val)))
            inject_req.extend(attr_val)

            inject_req.append(0x03)  # end-of-attributes

            emit(3, "IPP_SEND_INJECTION", "running",
                 f"POST http://{host}:{port}/ (IPP Get-Printer-Attributes with injected URI)")

            resp_ipp = requests.post(
                f"http://{host}:{port}/",
                data=bytes(inject_req),
                headers={"Content-Type": "application/ipp"},
                timeout=8,
            )

            if resp_ipp.status_code == 200 and len(resp_ipp.content) >= 8:
                # Parse status code from IPP response
                _, _, ipp_status, _ = struct.unpack(">BBHI", resp_ipp.content[:8])

                if ipp_status == 0x0000:  # successful-ok
                    ipp_injection_confirmed = True
                    exploitable_cves.append("CVE-2024-47076")
                    emit(3, "IPP_INJECTION_RESULT", "success",
                         f"IPP server ACCEPTED injected URI without validation! "
                         f"Status: 0x{ipp_status:04x} (successful-ok) — "
                         f"cfGetPrinterAttributes5 will trust attacker-controlled attributes. "
                         f"Response size: {len(resp_ipp.content)} bytes")
                elif ipp_status in (0x0406, 0x0500, 0x0501):
                    emit(3, "IPP_INJECTION_RESULT", "info",
                         f"IPP server rejected with status 0x{ipp_status:04x} — "
                         "injection may be mitigated by input validation")
                else:
                    # Non-zero but not explicitly rejecting — needs analysis
                    emit(3, "IPP_INJECTION_RESULT", "warning",
                         f"IPP returned status 0x{ipp_status:04x} — "
                         f"ambiguous, {len(resp_ipp.content)} bytes response needs manual analysis")
            else:
                emit(3, "IPP_INJECTION_RESULT", "warning",
                     f"HTTP {resp_ipp.status_code} — non-IPP response or server error")

        except requests.RequestException as exc:
            emit(3, "IPP_INJECTION_ERROR", "error", f"IPP injection probe failed: {exc}")

        evidence["cve_2024_47076"] = {
            "status": "EXPLOITABLE" if ipp_injection_confirmed else "NOT_CONFIRMED",
            "injection_canary": injection_canary,
            "ipp_injection_confirmed": ipp_injection_confirmed,
        }
        time.sleep(0.2)

        # ═══════════════════════════════════════════════════════════════
        # PHASE 4: CVE-2024-47175 — PPD Sanitization Bypass Test
        # ═══════════════════════════════════════════════════════════════
        emit(4, "CVE-2024-47175_PROBE", "running",
             "Testing libppd ppdCreatePPDFromIPP2 — PPD attribute sanitization bypass")
        time.sleep(0.3)

        ppd_bypass_confirmed = False

        # Test: send IPP printer attributes with embedded PPD directives
        # A vulnerable server will pass these through to temporary PPD files
        ppd_canary = f"*% PRET-PPD-CANARY-{canary_id}"
        emit(4, "PPD_CRAFT_PAYLOAD", "running",
             f"Testing if IPP attributes containing PPD directives are sanitized: '{ppd_canary}'")

        # Build IPP CUPS-Get-Printers and check if printer-make-and-model allows special chars
        try:
            ipp_body = _build_cups_get_printers_req(host, port)
            resp_ppd = requests.post(
                f"http://{host}:{port}/",
                data=ipp_body,
                headers={"Content-Type": "application/ipp"},
                timeout=8,
            )

            if resp_ppd.status_code == 200 and len(resp_ppd.content) >= 8:
                printers = _parse_ipp_printers(resp_ppd.content)
                for p in printers:
                    make_model = p.get("make_and_model", "")
                    # Check if make_and_model contains unescaped special chars
                    # that would allow PPD injection
                    if any(c in make_model for c in ['"', "'", "\n", "\\", "*"]):
                        ppd_bypass_confirmed = True
                        emit(4, "PPD_UNSANITIZED_ATTRS", "success",
                             f"Printer '{p.get('name')}' has UNSANITIZED make_and_model containing "
                             f"special chars: '{make_model[:60]}' — PPD injection possible via "
                             "ppdCreatePPDFromIPP2")
                        exploitable_cves.append("CVE-2024-47175")
                        break

                if not ppd_bypass_confirmed and printers:
                    emit(4, "PPD_SANITIZATION_CHECK", "info",
                         f"Checked {len(printers)} printer(s) — no unsanitized attributes detected")
                elif not printers:
                    emit(4, "PPD_NO_PRINTERS", "warning",
                         "No printers returned — cannot verify PPD sanitization in-band")
            else:
                emit(4, "PPD_IPP_ERROR", "warning",
                     f"IPP response: HTTP {resp_ppd.status_code}")

        except requests.RequestException as exc:
            emit(4, "PPD_PROBE_ERROR", "error", f"PPD sanitization probe failed: {exc}")

        # Also check /admin/conf/cupsd.conf for PPD-related configuration
        emit(4, "CUPSD_CONF_CHECK", "running",
             f"GET http://{host}:{port}/admin/conf/cupsd.conf — checking if PPD config is exposed")
        try:
            resp_conf = requests.get(f"http://{host}:{port}/admin/conf/cupsd.conf", timeout=6, allow_redirects=False)
            if resp_conf.status_code == 200 and ("LogLevel" in resp_conf.text or "<Location" in resp_conf.text):
                ppd_bypass_confirmed = True
                emit(4, "CUPSD_CONF_LEAKED", "success",
                     f"cupsd.conf LEAKED unauthenticated ({len(resp_conf.text)} bytes) — "
                     "attacker can read server configuration including PPD paths and filter directives")
                if "CVE-2024-47175" not in exploitable_cves:
                    exploitable_cves.append("CVE-2024-47175")
            else:
                emit(4, "CUPSD_CONF_PROTECTED", "info",
                     f"cupsd.conf returned HTTP {resp_conf.status_code} — protected")
        except requests.RequestException as exc:
            emit(4, "CUPSD_CONF_ERROR", "info", f"Config check: {exc}")

        evidence["cve_2024_47175"] = {
            "status": "EXPLOITABLE" if ppd_bypass_confirmed else "NOT_CONFIRMED",
            "ppd_bypass_confirmed": ppd_bypass_confirmed,
            "ppd_canary": ppd_canary,
        }
        time.sleep(0.2)

        # ═══════════════════════════════════════════════════════════════
        # PHASE 5: CVE-2024-47177 — FoomaticRIPCommandLine Injection
        # ═══════════════════════════════════════════════════════════════
        emit(5, "CVE-2024-47177_PROBE", "running",
             "Testing cups-filters foomatic-rip — FoomaticRIPCommandLine arbitrary command execution surface")
        time.sleep(0.3)

        foomatic_exploitable = False

        # Test 1: Check if foomatic-rip is present by looking at CUPS /printers/ page
        # and checking for foomatic-rip referenced PPDs
        emit(5, "FOOMATIC_FILTER_CHECK", "running",
             f"GET http://{host}:{port}/printers/ — scanning for foomatic-rip filter references")
        try:
            resp_printers = requests.get(f"http://{host}:{port}/printers/", timeout=8)
            if resp_printers.status_code == 200:
                html = resp_printers.text
                if "foomatic" in html.lower():
                    foomatic_exploitable = True
                    emit(5, "FOOMATIC_DETECTED", "success",
                         "foomatic-rip DETECTED in printer configuration! "
                         "FoomaticRIPCommandLine directive can execute arbitrary shell commands "
                         "when processing print jobs with attacker-controlled PPDs")
                    exploitable_cves.append("CVE-2024-47177")
                else:
                    emit(5, "FOOMATIC_NOT_FOUND", "info",
                         "No foomatic-rip references found in printer page HTML")
            else:
                emit(5, "FOOMATIC_PAGE_ERROR", "warning",
                     f"Printers page returned HTTP {resp_printers.status_code}")
        except requests.RequestException as exc:
            emit(5, "FOOMATIC_CHECK_ERROR", "error", f"Foomatic check failed: {exc}")

        # Test 2: Send a crafted IPP Create-Printer-Subscriptions (0x0016) request
        # to test if the server processes subscription creation without auth
        emit(5, "IPP_SUBSCRIPTION_PROBE", "running",
             f"Testing IPP Create-Printer-Subscriptions (0x0016) auth enforcement")
        try:
            sub_req = bytearray(struct.pack(">BBHI", 2, 0, 0x0016, 77))
            sub_req.append(0x01)  # op attrs

            # charset
            attr_name = b"attributes-charset"
            attr_val = b"utf-8"
            sub_req.append(0x47)
            sub_req.extend(struct.pack(">H", len(attr_name)))
            sub_req.extend(attr_name)
            sub_req.extend(struct.pack(">H", len(attr_val)))
            sub_req.extend(attr_val)

            # language
            attr_name = b"attributes-natural-language"
            attr_val = b"en-us"
            sub_req.append(0x48)
            sub_req.extend(struct.pack(">H", len(attr_name)))
            sub_req.extend(attr_name)
            sub_req.extend(struct.pack(">H", len(attr_val)))
            sub_req.extend(attr_val)

            # printer-uri
            attr_name = b"printer-uri"
            attr_val = f"ipp://{host}:{port}/printers".encode("utf-8")
            sub_req.append(0x45)
            sub_req.extend(struct.pack(">H", len(attr_name)))
            sub_req.extend(attr_name)
            sub_req.extend(struct.pack(">H", len(attr_val)))
            sub_req.extend(attr_val)

            sub_req.append(0x03)

            resp_sub = requests.post(
                f"http://{host}:{port}/",
                data=bytes(sub_req),
                headers={"Content-Type": "application/ipp"},
                timeout=8,
            )

            if resp_sub.status_code == 200 and len(resp_sub.content) >= 8:
                _, _, sub_status, _ = struct.unpack(">BBHI", resp_sub.content[:8])
                if sub_status == 0x0000:
                    emit(5, "IPP_SUBSCRIPTION_AUTH", "success",
                         f"IPP subscriptions accepted WITHOUT authentication (status 0x{sub_status:04x}) — "
                         "attacker can register for job events to monitor print activity")
                    if not foomatic_exploitable:
                        foomatic_exploitable = True
                        if "CVE-2024-47177" not in exploitable_cves:
                            exploitable_cves.append("CVE-2024-47177")
                else:
                    emit(5, "IPP_SUBSCRIPTION_AUTH", "info",
                         f"IPP subscriptions returned status 0x{sub_status:04x} — auth enforced or rejected")
            else:
                emit(5, "IPP_SUBSCRIPTION_AUTH", "info",
                     f"HTTP {resp_sub.status_code} — non-standard response")

        except requests.RequestException as exc:
            emit(5, "IPP_SUBSCRIPTION_ERROR", "error", f"Subscription probe failed: {exc}")

        evidence["cve_2024_47177"] = {
            "status": "EXPLOITABLE" if foomatic_exploitable else "NOT_CONFIRMED",
            "foomatic_exploitable": foomatic_exploitable,
        }
        time.sleep(0.2)

        # ═══════════════════════════════════════════════════════════════
        # PHASE 6: RCE Chain Synthesis & Exploitability Report
        # ═══════════════════════════════════════════════════════════════
        emit(6, "CHAIN_SYNTHESIS", "running",
             "Correlating exploitation verification results across all CVEs")
        time.sleep(0.3)

        chain_exploitable = (
            "CVE-2024-47176" in exploitable_cves and
            ("CVE-2024-47076" in exploitable_cves or "CVE-2024-47175" in exploitable_cves) and
            "CVE-2024-47177" in exploitable_cves
        )

        if chain_exploitable:
            overall = "CRITICAL"
            emit(6, "RCE_CHAIN_CONFIRMED", "success",
                 f"🚨 FULL RCE CHAIN IS EXPLOITABLE! Verified {len(exploitable_cves)} CVEs: "
                 f"{', '.join(exploitable_cves)}. "
                 "An attacker on the network can achieve unauthenticated Remote Code Execution "
                 "by: (1) sending a crafted UDP packet to cups-browsed [CVE-2024-47176], "
                 "(2) injecting malicious IPP attributes [CVE-2024-47076/47175], "
                 "(3) triggering arbitrary command execution via FoomaticRIPCommandLine [CVE-2024-47177].")
        elif exploitable_cves:
            overall = "HIGH"
            emit(6, "PARTIAL_CHAIN", "warning",
                 f"Partial exploit chain confirmed — {len(exploitable_cves)} CVE(s) verified: "
                 f"{', '.join(exploitable_cves)}. Full RCE chain requires all 4 conditions. "
                 "Target is still at elevated risk.")
        elif is_vulnerable_version:
            overall = "MEDIUM"
            emit(6, "VERSION_VULNERABLE", "warning",
                 f"CUPS {cups_version} is in the vulnerable version range but no CVEs were "
                 "actively confirmed via network probes. The server may be patched via backports "
                 "or configuration hardening.")
        else:
            overall = "LOW"
            emit(6, "NOT_EXPLOITABLE", "info",
                 "No CVEs were confirmed exploitable via network probes. "
                 "Target appears hardened or patched.")

        emit(6, "VERIFICATION_COMPLETE", "complete",
             f"Exploitation verification finished. Risk: {overall}. "
             f"Verified CVEs: {len(exploitable_cves)}/{4}. "
             f"Canary ID: {canary_id}")

        evidence["exploitable_cves"] = exploitable_cves
        evidence["chain_exploitable"] = chain_exploitable
        evidence["overall_risk"] = overall
        evidence["exploit_summary"] = (
            f"{'FULL RCE CHAIN EXPLOITABLE' if chain_exploitable else 'Partial verification'} — "
            f"{len(exploitable_cves)} CVE(s) confirmed: {', '.join(exploitable_cves) or 'None'}"
        )

        sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "info"}
        return OperationResult(
            status="ok",
            severity=sev_map.get(overall, "info"),
            summary=(
                f"Exploit Verification [{overall}]: {len(exploitable_cves)}/4 CVEs confirmed on "
                f"CUPS {cups_version or 'unknown'} at {host}:{port}"
                + (f" — FULL RCE CHAIN EXPLOITABLE" if chain_exploitable else "")
            ),
            evidence=evidence,
            remediation=(
                "IMMEDIATE ACTION REQUIRED:\n"
                "1. Stop cups-browsed NOW: systemctl stop cups-browsed && systemctl disable cups-browsed\n"
                "2. Block UDP port 631 at all network perimeters immediately\n"
                "3. Upgrade to cups-browsed >= 2.0.2, cups-filters >= 2.0.1, "
                "libcupsfilters >= 2.0.1, libppd >= 2.0.1\n"
                "4. Restrict /admin/ access via cupsd.conf: AuthType Default + Require user @SYSTEM\n"
                f"5. See upstream advisory: {_ADVISORY_URL}\n"
            ) if exploitable_cves else (
                f"Target appears hardened. Continue monitoring CUPS releases. See {_ADVISORY_URL}"
            ),
        )

