"""
WSD (Web Services on Devices / WS-Discovery) adapter.
See pret-web-ui-docs/13-WSD-ADAPTER-DESIGN.md.

Implements:
1. Multicast / unicast WS-Discovery probe on UDP port 3702.
2. WS-Transfer / DPWS metadata extraction over HTTP (default port 5357 or 80).
3. Read-only identification and capability introspection.
"""
from __future__ import annotations

import re
import socket
import time
import uuid
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

import requests

from .base import Adapter, Operation, OperationResult, ValidateCallback

WS_DISCOVERY_MULTICAST = "239.255.255.250"
WS_DISCOVERY_PORT = 3702
DPWS_DEFAULT_HTTP_PORT = 5357

# Safe XML namespaces used in WS-Discovery and DPWS
NAMESPACES = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "wsdp": "http://schemas.xmlsoap.org/ws/2006/02/devprof",
    "pnpx": "http://schemas.microsoft.com/windows/pnpx/2005/10",
}


def _build_probe_xml(types: str = "wsdp:Device") -> bytes:
    msg_id = f"urn:uuid:{uuid.uuid4()}"
    envelope = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>{msg_id}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wsd:Probe>
      <wsd:Types>{types}</wsd:Types>
    </wsd:Probe>
  </soap:Body>
</soap:Envelope>"""
    return envelope.encode("utf-8")


def _parse_probe_match(raw_xml: str | bytes) -> dict[str, Any] | None:
    try:
        root = ET.fromstring(raw_xml)
    except Exception:
        return None

    # Search for ProbeMatch elements
    matches = root.findall(".//{http://schemas.xmlsoap.org/ws/2005/04/discovery}ProbeMatch")
    if not matches:
        return None

    match = matches[0]
    ep_elem = match.find(".//{http://schemas.xmlsoap.org/ws/2004/08/addressing}Address")
    types_elem = match.find("{http://schemas.xmlsoap.org/ws/2005/04/discovery}Types")
    xaddrs_elem = match.find("{http://schemas.xmlsoap.org/ws/2005/04/discovery}XAddrs")

    endpoint = ep_elem.text.strip() if ep_elem is not None and ep_elem.text else ""
    types = types_elem.text.strip() if types_elem is not None and types_elem.text else ""
    xaddrs = xaddrs_elem.text.strip().split() if xaddrs_elem is not None and xaddrs_elem.text else []

    return {
        "endpoint": endpoint,
        "types": types,
        "xaddrs": xaddrs,
    }


def browse_for_wsd_printers(timeout_seconds: float = 3.0) -> list[dict[str, Any]]:
    """
    Sends WS-Discovery multicast probe and returns a list of discovered devices:
    [{"address": "192.168.1.50", "endpoint": "urn:uuid:...", "xaddrs": [...], "types": ...}]
    """
    probe_pkt = _build_probe_xml("wsdp:Device")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.5)

    try:
        sock.sendto(probe_pkt, (WS_DISCOVERY_MULTICAST, WS_DISCOVERY_PORT))
    except Exception:
        # On some network interfaces or configurations where multicast route is absent
        sock.close()
        return []

    discovered = []
    seen_ips = set()
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(65535)
            ip = addr[0]
            parsed = _parse_probe_match(data)
            if parsed and ip not in seen_ips:
                seen_ips.add(ip)
                parsed["address"] = ip
                discovered.append(parsed)
        except socket.timeout:
            continue
        except OSError:
            break

    sock.close()
    return discovered


def _fetch_dpws_metadata(target_url: str, validate_cb: ValidateCallback | None = None) -> dict[str, str]:
    """
    Retrieves DPWS metadata from device HTTP/WSD endpoint safely.
    Validates host before connecting and avoids entity expansion.
    """
    parsed_url = urlparse(target_url)
    host = parsed_url.hostname or target_url
    if validate_cb:
        validate_cb(host)

    get_envelope = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2004:09:transfer</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>
    <wsa:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</wsa:MessageID>
  </soap:Header>
  <soap:Body/>
</soap:Envelope>"""

    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "User-Agent": "PRET-Web-WSD/1.0",
    }

    resp = requests.post(
        target_url,
        data=get_envelope.encode("utf-8"),
        headers=headers,
        timeout=4.0,
        allow_redirects=False,
    )

    metadata: dict[str, str] = {}
    if resp.status_code == 200:
        try:
            root = ET.fromstring(resp.content)
            for tag in ["Manufacturer", "ModelName", "ModelNumber", "FriendlyName", "SerialNumber", "FirmwareVersion"]:
                for elem in root.iter():
                    if elem.tag.endswith(tag) and elem.text:
                        metadata[tag] = elem.text.strip()
                        break
        except Exception:
            pass

    return metadata


class WSDAdapter(Adapter):
    id = "wsd"
    display_name = "WSD (Web Services on Devices)"

    def dependency_status(self) -> dict:
        return {"available": True, "detail": "Pure-Python WS-Discovery & DPWS client active"}

    def list_operations(self) -> list[Operation]:
        return [
            Operation(
                id="wsd_identify",
                display_name="WSD Device Identification",
                read_only=True,
                description="Probe target on WSD/DPWS ports (UDP 3702, TCP 5357) for model, vendor, and UUID.",
            ),
            Operation(
                id="wsd_printer_summary",
                display_name="WSD Printer Metadata Summary",
                read_only=True,
                description="Retrieve detailed DPWS metadata and exposed service endpoints.",
            ),
        ]

    def run_operation(
        self,
        op_id: str,
        target_host: str,
        target_port: int,
        params: dict[str, Any],
        progress_cb: Any = None,
        validate_cb: ValidateCallback | None = None,
    ) -> OperationResult:
        if progress_cb:
            progress_cb(f"Starting WSD operation '{op_id}' on {target_host}...")

        # 1. First probe via unicast UDP 3702 to see if WS-Discovery responds
        unicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        unicast_sock.settimeout(2.0)
        probe_pkt = _build_probe_xml("wsdp:Device")
        probe_result = None

        try:
            unicast_sock.sendto(probe_pkt, (target_host, WS_DISCOVERY_PORT))
            data, _ = unicast_sock.recvfrom(65535)
            probe_result = _parse_probe_match(data)
            if progress_cb:
                progress_cb(f"Received WS-Discovery response: {probe_result}")
        except Exception as exc:
            if progress_cb:
                progress_cb(f"WS-Discovery UDP probe timed out or unanswered ({exc}); trying HTTP/DPWS directly...")
        finally:
            unicast_sock.close()

        # 2. Try HTTP DPWS endpoint (port 5357 or target_port if specified)
        http_port = DPWS_DEFAULT_HTTP_PORT
        if probe_result and probe_result.get("xaddrs"):
            # Use XAddr if discovered
            xaddr = probe_result["xaddrs"][0]
        else:
            xaddr = f"http://{target_host}:{http_port}/"

        metadata: dict[str, str] = {}
        try:
            metadata = _fetch_dpws_metadata(xaddr, validate_cb=validate_cb)
            if progress_cb and metadata:
                progress_cb(f"Retrieved DPWS metadata: {metadata}")
        except Exception as exc:
            if progress_cb:
                progress_cb(f"DPWS metadata query note: {exc}")

        evidence = {
            "target": target_host,
            "ws_discovery": probe_result or "No UDP:3702 response",
            "dpws_metadata": metadata,
        }

        if not probe_result and not metadata:
            return OperationResult(
                status="error",
                severity="info",
                summary=f"No WSD/DPWS response from {target_host} on UDP:3702 or TCP:{http_port}",
                evidence=evidence,
                remediation="Target device does not have WSD enabled or filtered by firewall.",
                error_detail="No response on WS-Discovery or DPWS ports.",
            )

        model = metadata.get("ModelName") or metadata.get("FriendlyName") or "WSD Printer Device"
        vendor = metadata.get("Manufacturer") or "Unknown Vendor"
        uuid_ep = probe_result.get("endpoint") if probe_result else ""

        summary = f"Identified WSD device: {vendor} {model}"
        if uuid_ep:
            summary += f" ({uuid_ep})"

        return OperationResult(
            status="ok",
            severity="info",
            summary=summary,
            evidence=evidence,
            remediation="Ensure WSD is authenticated or firewalled if not needed in untrusted subnets.",
        )
