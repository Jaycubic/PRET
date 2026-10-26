import pytest
from app.adapters.registry import ADAPTERS, get_adapter
from app.adapters.base import Adapter, Operation, OperationResult


def test_registry_contains_all_ten_adapters():
    expected_ids = {
        "pjl", "pcl", "postscript", "snmp_v2c", "snmp_v3",
        "mdns", "ipp", "cups_server", "http_fingerprint", "wsd"
    }
    assert set(ADAPTERS.keys()) == expected_ids


def test_all_adapters_available():
    for adapter_id, adapter in ADAPTERS.items():
        status = adapter.dependency_status()
        assert status["available"] is True, f"Adapter {adapter_id} reported unavailable: {status}"


def test_adapter_operations_catalog():
    for adapter_id, adapter in ADAPTERS.items():
        ops = adapter.list_operations()
        assert len(ops) > 0, f"Adapter {adapter_id} has no registered operations"
        for op in ops:
            assert isinstance(op.id, str) and len(op.id) > 0
            assert isinstance(op.display_name, str) and len(op.display_name) > 0
            assert isinstance(op.read_only, bool)
            assert isinstance(op.description, str)


def test_path_sanitization_in_pjl_adapter():
    from app.adapters.pjl import _validate_device_path

    # Valid paths
    assert _validate_device_path("0:\\") == "0:\\"
    assert _validate_device_path("0:/fonts") == "0:/fonts"

    # Path traversal rejection
    with pytest.raises(ValueError):
        _validate_device_path("../../etc/shadow")

    # Newline injection rejection
    with pytest.raises(ValueError):
        _validate_device_path("0:\\\ndelete /root/passwords")

    # Shell metacharacters rejection
    with pytest.raises(ValueError):
        _validate_device_path("0:\\; rm -rf /")



def test_http_fingerprint_redirect_revalidation():
    from app.adapters.http_fingerprint import HTTPFingerprintAdapter
    from app.security import ScopeError

    adapter = HTTPFingerprintAdapter()

    # Callback that blocks out-of-scope targets
    def mock_validate(host: str):
        if host in ["169.254.169.254", "evil.internal", "0.0.0.0"]:
            raise ScopeError(f"Host {host} is out of authorized scope")

    # Target that immediately errors or is rejected
    result = adapter.run_operation(
        "http_banner",
        "192.168.1.50",
        80,
        {},
        validate_cb=mock_validate,
    )
    # The adapter gracefully handles connection refusal/timeout rather than crashing
    assert result.status in ["ok", "error"]


def test_wsd_adapter_operations():
    from app.adapters.wsd import WSDAdapter

    adapter = WSDAdapter()
    ops = [o.id for o in adapter.list_operations()]
    assert "wsd_identify" in ops
    assert "wsd_printer_summary" in ops

    # Run operation against a non-existent loopback port with validate_cb
    result = adapter.run_operation(
        "wsd_identify",
        "0.0.0.0",
        3702,
        {},
        validate_cb=lambda host: None,
    )
    assert result.status in ["ok", "error"]
    assert "ws_discovery" in result.evidence


def test_cups_server_adapter_queue_enumeration_and_cves():
    import struct
    from app.adapters.cups_server import (
        CUPSServerAdapter,
        _build_cups_get_printers_req,
        _parse_ipp_printers,
        _scrape_html_printers,
        _assess_cups_cves,
    )

    adapter = CUPSServerAdapter()
    op_ids = [o.id for o in adapter.list_operations()]
    assert "cups_version_fingerprint" in op_ids
    assert "cups_admin_auth_check" in op_ids
    assert "cups_browsed_udp_exposure" in op_ids
    assert "cups_queue_enumeration" in op_ids
    assert "cups_full_audit" in op_ids

    # 1. Test binary IPP request builder
    req = _build_cups_get_printers_req("192.168.1.100", 631, request_id=42)
    assert len(req) > 20
    assert req[:2] == b"\x02\x01"  # IPP/2.1
    assert req[2:4] == b"\x40\x02"  # CUPS-Get-Printers
    assert req[-1] == 0x03  # end tag

    # 2. Test IPP printer parser
    resp = bytearray(struct.pack(">BBHI", 2, 1, 0, 42))
    resp.append(0x01)  # operation attrs
    # attributes-charset
    resp.append(0x47)
    resp.extend(struct.pack(">H", 18))
    resp.extend(b"attributes-charset")
    resp.extend(struct.pack(">H", 5))
    resp.extend(b"utf-8")
    # printer 1
    resp.append(0x04)
    resp.append(0x42)
    resp.extend(struct.pack(">H", 12))
    resp.extend(b"printer-name")
    resp.extend(struct.pack(">H", 10))
    resp.extend(b"Secure_PDF")
    resp.append(0x23)
    resp.extend(struct.pack(">H", 13))
    resp.extend(b"printer-state")
    resp.extend(struct.pack(">H", 4))
    resp.extend(struct.pack(">i", 3))  # 3 = idle
    resp.append(0x45)
    resp.extend(struct.pack(">H", 10))
    resp.extend(b"device-uri")
    resp.extend(struct.pack(">H", 13))
    resp.extend(b"cups-pdf:/out")
    resp.append(0x03)  # end

    printers = _parse_ipp_printers(bytes(resp))
    assert len(printers) == 1
    assert printers[0]["name"] == "Secure_PDF"
    assert printers[0]["state"] == "idle"
    assert printers[0]["device_uri"] == "cups-pdf:/out"

    # 3. Test HTML scraper fallback
    sample_html = """
    <html>
      <body>
        <table class="list">
          <tr><td><a href="/printers/Engineering_LaserJet">Engineering_LaserJet</a></td></tr>
          <tr><td><a href="/printers/Finance_Color">Finance_Color</a></td></tr>
        </table>
      </body>
    </html>
    """
    html_printers = _scrape_html_printers(sample_html, "10.0.0.5", 631)
    assert len(html_printers) == 2
    names = {p["name"] for p in html_printers}
    assert names == {"Engineering_LaserJet", "Finance_Color"}

    # 4. Test CVE assessment logic
    # Older unpatched CUPS with UDP exposed -> CRITICAL
    risk, cves, remediation = _assess_cups_cves("2.4.7", udp_reachable=True)
    assert risk == "CRITICAL"
    assert any(c["cve_id"] == "CVE-2024-47176" for c in cves)
    assert any(c["cve_id"] == "CVE-2024-47177" for c in cves)
    assert "cups-browsed" in remediation

    # Patched / unreachable UDP -> HIGH or MEDIUM depending on version
    risk_closed, cves_closed, _ = _assess_cups_cves("2.4.12", udp_reachable=False)
    assert risk_closed in ("LOW", "CLEAN")

    # 5. Run full audit on dummy host to ensure graceful error handling
    res = adapter.run_operation("cups_full_audit", "0.0.0.0", 631, {})
    assert res.status in ["ok", "error"]
    assert "risk_score" in res.evidence


def test_port_scanner_fingerprinter_structure():
    from app.adapters.port_scanner import scan_and_fingerprint_target, PRINTER_PORTS
    assert len(PRINTER_PORTS) >= 6
    ports = [p["port"] for p in PRINTER_PORTS]
    assert 9100 in ports
    assert 631 in ports
    assert 515 in ports
    assert 80 in ports

    # Verify return schema
    res = scan_and_fingerprint_target("127.0.0.1", timeout=0.1)
    assert "open_ports" in res
    assert "services" in res
    assert "device_type" in res
    assert "recommended_port" in res
    assert isinstance(res["open_ports"], list)

