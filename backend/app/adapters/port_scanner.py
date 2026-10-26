"""
Pure-Python printer port scanner and service fingerprinter.
Probes standard printing, discovery, and management ports concurrently,
extracts protocol banners (PJL, IPP, HTTP, LPD), and determines the best
connection port and accurate device type (physical printer vs CUPS server).
"""
import concurrent.futures
import re
import socket
from typing import Any, Dict, List, Optional


PRINTER_PORTS = [
    {
        "port": 9100,
        "protocol": "RAW / JetDirect",
        "description": "AppSocket raw stream — primary port for PJL, PostScript, and PCL commands",
        "default_device_type": "printer",
        "priority": 1,
    },
    {
        "port": 631,
        "protocol": "IPP",
        "description": "Internet Printing Protocol / CUPS service",
        "default_device_type": "printer",
        "priority": 2,
    },
    {
        "port": 515,
        "protocol": "LPD / LPR",
        "description": "Line Printer Daemon RFC 1179 legacy spooler",
        "default_device_type": "printer",
        "priority": 3,
    },
    {
        "port": 80,
        "protocol": "HTTP",
        "description": "Embedded Web Server / printer management console",
        "default_device_type": "printer",
        "priority": 4,
    },
    {
        "port": 443,
        "protocol": "HTTPS",
        "description": "Secure Embedded Web Server (SSL/TLS)",
        "default_device_type": "printer",
        "priority": 5,
    },
    {
        "port": 5357,
        "protocol": "WSD",
        "description": "Web Services on Devices (WSD print service)",
        "default_device_type": "printer",
        "priority": 6,
    },
    {
        "port": 22,
        "protocol": "SSH",
        "description": "Secure Shell management console",
        "default_device_type": "printer",
        "priority": 7,
    },
]


def _probe_socket(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((ip, port))
        s.close()
        return res == 0
    except Exception:
        return False


def _grab_pjl_banner(ip: str, port: int = 9100, timeout: float = 2.0) -> Optional[str]:
    """Sends PJL INFO ID to JetDirect port 9100 to extract exact printer make/model."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(b"\x1b%-12345X@PJL \r\n@PJL INFO ID\r\n\x1b%-12345X")
        data = s.recv(512)
        s.close()
        text = data.decode("latin-1", errors="ignore")
        # Match quoted model e.g. "HP LaserJet Pro MFP M226dw"
        m = re.search(r'"([^"]+)"', text)
        if m:
            return m.group(1).strip()
        lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("@PJL")]
        if lines:
            return lines[0]
    except Exception:
        pass
    return None


def _grab_http_banner(ip: str, port: int = 80, timeout: float = 2.0) -> Dict[str, str]:
    """Inspects HTTP Server header and HTML title to identify printer brand/firmware."""
    res: Dict[str, str] = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: PRET-Web-Scanner/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        data = b""
        while len(data) < 2048:
            chunk = s.recv(512)
            if not chunk:
                break
            data += chunk
        s.close()

        text = data.decode("latin-1", errors="ignore")
        # Extract Server header
        m_srv = re.search(r"^Server:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
        if m_srv:
            res["server"] = m_srv.group(1).strip()

        # Extract Title
        m_title = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if m_title:
            res["title"] = m_title.group(1).strip()
    except Exception:
        pass
    return res


def _grab_ipp_fingerprint(ip: str, port: int = 631, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Sends IPP Get-Printer-Attributes to distinguish between a Linux CUPS server
    and a physical embedded IPP printer.
    """
    info: Dict[str, Any] = {"is_cups": False, "cups_version": None, "make_and_model": None}
    try:
        ipp_req = (
            b"\x01\x01"  # version 1.1
            b"\x00\x0b"  # Get-Printer-Attributes
            b"\x00\x00\x00\x01"  # request-id
            b"\x01"  # operation-attributes-tag
            b"\x47\x00\x12attributes-charset\x00\x05utf-8"
            b"\x48\x00\x1battributes-natural-language\x00\x02en"
            b"\x45\x00\x0bprinter-uri\x00\x16ipp://" + ip.encode() + b"/ipp/print"
            b"\x03"  # end-of-attributes-tag
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        http = (
            f"POST /ipp/print HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"Content-Type: application/ipp\r\n"
            f"Content-Length: {len(ipp_req)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + ipp_req
        s.sendall(http)

        resp = b""
        while len(resp) < 4096:
            chunk = s.recv(512)
            if not chunk:
                break
            resp += chunk
        s.close()

        # Check for CUPS signature in HTTP headers or body
        resp_lower = resp.lower()
        if b"cups/" in resp_lower or b"cupsd" in resp_lower:
            info["is_cups"] = True
            m = re.search(r"cups/([\d.]+)", resp.decode("latin-1", errors="ignore"), re.IGNORECASE)
            if m:
                info["cups_version"] = m.group(1)

        # Look for printer-make-and-model attribute
        if b"printer-make-and-model" in resp:
            idx = resp.find(b"printer-make-and-model")
            snippet = resp[idx : idx + 100].decode("latin-1", errors="ignore")
            # In IPP, text string follows tag and length
            m_model = re.search(r"printer-make-and-model[^\w]*([A-Za-z0-9][A-Za-z0-9\s._-]+)", snippet)
            if m_model:
                info["make_and_model"] = m_model.group(1).strip()
    except Exception:
        pass
    return info


def scan_and_fingerprint_target(ip: str, timeout: float = 1.5) -> Dict[str, Any]:
    """
    Scans standard printer ports concurrently, finger-prints services,
    and returns a structured inventory with recommended port and accurate device type.
    """
    open_port_ids: List[int] = []

    # 1. Concurrent port discovery
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_to_port = {
            executor.submit(_probe_socket, ip, item["port"], timeout): item["port"]
            for item in PRINTER_PORTS
        }
        for future in concurrent.futures.as_completed(future_to_port):
            p = future_to_port[future]
            try:
                if future.result():
                    open_port_ids.append(p)
            except Exception:
                pass

    # Sort ports according to priority list order
    open_port_ids.sort(key=lambda p: next((x["priority"] for x in PRINTER_PORTS if x["port"] == p), 99))

    detected_services: List[Dict[str, Any]] = []
    detected_model: Optional[str] = None
    is_cups_server = False
    cups_ver: Optional[str] = None

    # 2. Targeted banner grabbing on open ports
    pjl_banner = None
    if 9100 in open_port_ids:
        pjl_banner = _grab_pjl_banner(ip, 9100)
        if pjl_banner:
            detected_model = pjl_banner

    ipp_info = None
    if 631 in open_port_ids:
        ipp_info = _grab_ipp_fingerprint(ip, 631)
        if ipp_info.get("is_cups"):
            is_cups_server = True
            cups_ver = ipp_info.get("cups_version")
        if not detected_model and ipp_info.get("make_and_model"):
            detected_model = ipp_info.get("make_and_model")

    http_info = None
    if 80 in open_port_ids or 443 in open_port_ids:
        p = 80 if 80 in open_port_ids else 443
        http_info = _grab_http_banner(ip, p)
        if not detected_model and http_info.get("title") and len(http_info["title"]) < 50:
            detected_model = http_info["title"]

    # 3. Determine device type & recommended port
    # A device is only classified as a "print_server" if it genuinely identifies as CUPS.
    # Physical printers (HP, Brother, Epson, etc.) running IPP on 631 are classified as "printer"!
    device_type = "print_server" if is_cups_server else "printer"

    # Recommended port:
    # If it's a physical printer and 9100 is open, 9100 is optimal for raw PJL/PostScript/PCL.
    # If 9100 is closed but 631 is open, use 631.
    # If it's a CUPS server, default to 631.
    if is_cups_server and 631 in open_port_ids:
        recommended_port = 631
    elif 9100 in open_port_ids:
        recommended_port = 9100
    elif 631 in open_port_ids:
        recommended_port = 631
    elif 515 in open_port_ids:
        recommended_port = 515
    elif 80 in open_port_ids:
        recommended_port = 80
    elif open_port_ids:
        recommended_port = open_port_ids[0]
    else:
        recommended_port = 9100

    # Build services list
    for p in open_port_ids:
        meta = next((x for x in PRINTER_PORTS if x["port"] == p), None)
        proto = meta["protocol"] if meta else "TCP"
        desc = meta["description"] if meta else ""

        banner_str = None
        if p == 9100 and pjl_banner:
            banner_str = f"PJL: {pjl_banner}"
        elif p == 631:
            if is_cups_server:
                banner_str = f"CUPS {cups_ver or ''} (Print Server Daemon)".strip()
            elif ipp_info and ipp_info.get("make_and_model"):
                banner_str = f"IPP: {ipp_info['make_and_model']}"
            else:
                banner_str = "IPP 1.1 / 2.0 (Physical Printer Endpoint)"
        elif p in (80, 443) and http_info:
            parts = []
            if http_info.get("server"):
                parts.append(f"Server: {http_info['server']}")
            if http_info.get("title"):
                parts.append(f"Title: {http_info['title']}")
            banner_str = " | ".join(parts) if parts else None

        detected_services.append({
            "port": p,
            "protocol": proto,
            "description": desc,
            "banner": banner_str,
            "is_recommended": (p == recommended_port),
        })

    return {
        "ip": ip,
        "open_ports": open_port_ids,
        "services": detected_services,
        "detected_model": detected_model,
        "device_type": device_type,
        "is_cups_server": is_cups_server,
        "cups_version": cups_ver,
        "recommended_port": recommended_port,
        "summary": (
            f"Found {len(open_port_ids)} open printer ports on {ip}. "
            f"Identified as {device_type.replace('_', ' ').title()}"
            + (f" ({detected_model})" if detected_model else "")
            + f", recommended port: {recommended_port} ({next((s['protocol'] for s in detected_services if s['port'] == recommended_port), 'RAW')})."
        ),
    }
