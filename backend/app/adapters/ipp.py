"""
IPP / IPPS adapter — real implementation using `pyipp` (actively
maintained, used by Home Assistant's IPP printer integration; API
confirmed directly against the installed package during this session,
not assumed from memory).

Security note (05-SECURITY-ARCHITECTURE.md §4): pyipp defaults to
verify_ssl=False for IPPS. This adapter does NOT inherit that default —
it explicitly passes verify_ssl=True unless the caller opts into an
explicit, per-operation "trust_self_signed" parameter, which is the
"per-target, explicit, audited exception" the security doc requires
instead of a blanket relaxed-verification default.
"""
from __future__ import annotations

import asyncio

from .base import Adapter, Operation, OperationParam, OperationResult

try:
    from pyipp import IPP, IPPConnectionError, IPPError
    _PYIPP_AVAILABLE = True
    _PYIPP_IMPORT_ERROR = ""
except ImportError as exc:
    _PYIPP_AVAILABLE = False
    _PYIPP_IMPORT_ERROR = str(exc)


async def _query_printer(host: str, port: int, tls: bool, verify_ssl: bool, timeout: int = 8):
    ipp = IPP(host, port=port, tls=tls, verify_ssl=verify_ssl, request_timeout=timeout)
    try:
        printer = await ipp.printer()
        return printer, None
    except IPPConnectionError as exc:
        return None, f"connection error: {exc}"
    except IPPError as exc:
        return None, f"IPP error: {exc}"
    finally:
        await ipp.close()


def _printer_to_dict(printer) -> dict:
    info = printer.info
    state = printer.state
    return {
        "name": getattr(info, "name", None),
        "printer_info": getattr(info, "printer_info", None),
        "manufacturer": getattr(info, "manufacturer", None),
        "model": getattr(info, "model", None),
        "printer_uri_supported": getattr(info, "printer_uri_supported", None),
        "serial": getattr(info, "serial", None),
        "uuid": getattr(info, "uuid", None),
        "version": getattr(info, "version", None),
        "state": getattr(state, "printer_state", None),
        "state_reasons": getattr(state, "reasons", None),
        "markers": [
            {"name": m.name, "level": m.level, "type": m.marker_type}
            for m in (printer.markers or [])
        ],
    }


class IPPAdapter(Adapter):
    id = "ipp"
    display_name = "IPP / IPPS"
    platform_support = {"linux": True, "windows": True}

    def dependency_status(self) -> dict:
        if not _PYIPP_AVAILABLE:
            return {"available": False, "detail": f"pyipp not installed: {_PYIPP_IMPORT_ERROR}"}
        return {"available": True, "detail": ""}

    def list_operations(self) -> list[Operation]:
        return [
            Operation(
                id="ipp_get_printer_attributes",
                display_name="Get Device Info (IPP)",
                read_only=True,
                description="Queries get-printer-attributes over plain IPP (port 631).",
            ),
            Operation(
                id="ipps_get_printer_attributes",
                display_name="Get Device Info (IPPS/TLS)",
                read_only=True,
                description="Queries get-printer-attributes over IPPS (TLS). Verifies "
                             "the certificate by default — use "
                             "ipps_get_printer_attributes_trust_self_signed if the "
                             "device uses a self-signed cert you've already vetted.",
            ),
            Operation(
                id="ipps_get_printer_attributes_trust_self_signed",
                display_name="Get Device Info (IPPS, trust self-signed)",
                read_only=True,
                description="Same as above, but explicitly disables certificate "
                             "verification for THIS target. Use only after you've "
                             "manually verified the device's self-signed cert — this "
                             "is the explicit, audited exception "
                             "05-SECURITY-ARCHITECTURE.md §4 requires, not a default.",
            ),
        ]

    def run_operation(self, operation_id, resolved_ip, port, params, progress_cb=None, validate_cb=None) -> OperationResult:
        if not _PYIPP_AVAILABLE:
            return OperationResult(status="unsupported",
                                    error_detail=f"pyipp not available: {_PYIPP_IMPORT_ERROR}")

        if operation_id == "ipp_get_printer_attributes":
            tls, verify_ssl, use_port = False, True, port or 631
        elif operation_id == "ipps_get_printer_attributes":
            tls, verify_ssl, use_port = True, True, port or 631
        elif operation_id == "ipps_get_printer_attributes_trust_self_signed":
            tls, verify_ssl, use_port = True, False, port or 631
        else:
            return OperationResult(status="unsupported", error_detail=f"Unknown operation {operation_id}")

        if progress_cb:
            progress_cb(f"IPP get-printer-attributes {resolved_ip}:{use_port} (tls={tls})")

        try:
            printer, error = asyncio.run(_query_printer(resolved_ip, use_port, tls, verify_ssl))
        except Exception as exc:
            return OperationResult(status="error", error_detail=str(exc))

        if error:
            return OperationResult(status="ok", summary=f"No IPP response: {error}",
                                    evidence={"error": error})

        evidence = _printer_to_dict(printer)
        return OperationResult(
            status="ok",
            summary=f"IPP attributes retrieved: {evidence.get('manufacturer')} {evidence.get('model')}",
            evidence=evidence,
        )
