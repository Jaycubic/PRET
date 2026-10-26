"""
SNMP v1/v2c adapter — real implementation using the actively maintained
`pysnmp` package (the lextudio-maintained continuation; the original
etingof/pysnmp is unmaintained, confirmed in
pret-web-ui-docs/03-PROTOCOL-EXPANSION.md).

Addresses the Phase 1 finding that upstream PRET's own SNMP support
(discovery.py/capabilities.py) is v1-only, wraps an unmaintained library,
and silently degrades when the dependency is missing. This adapter is a
clean-room implementation against the maintained library, not a wrapper
around PRET's SNMP code, and dependency_status() reports availability
honestly rather than failing silently — directly fixing that finding.

Read-only only. No community-string brute-forcing in v1 — see
05-SECURITY-ARCHITECTURE.md's note on not brute-forcing credentials by
default; a default/weak community string finding is reported if a
*provided* common default happens to work, not searched for exhaustively.
"""
from __future__ import annotations

import asyncio

from .base import Adapter, Operation, OperationParam, OperationResult

try:
    from pysnmp.hlapi.v1arch.asyncio import (
        CommunityData, UdpTransportTarget, ObjectType, ObjectIdentity,
        SnmpDispatcher, get_cmd,
    )
    _PYSNMP_AVAILABLE = True
    _PYSNMP_IMPORT_ERROR = ""
except ImportError as exc:  # mirrors the real degradation PRET's own
    # discovery.py has, but reported honestly via dependency_status()
    # instead of a silent flag nobody surfaces to the UI.
    _PYSNMP_AVAILABLE = False
    _PYSNMP_IMPORT_ERROR = str(exc)

# Standard printer-relevant OIDs. sysDescr/sysName/sysUpTime are generic
# SNMPv2-MIB; the rest are from the Printer MIB (RFC 3805).
_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "prtGeneralSerialNumber": "1.3.6.1.2.1.43.5.1.1.17.1",
    "hrDeviceDescr": "1.3.6.1.2.1.25.3.2.1.3.1",
}

_COMMON_DEFAULT_COMMUNITIES = ["public"]  # read-only, widely-documented
# default — checking THIS specific, well-known default is standard
# vulnerability-scanner practice (same category as checking a printer's
# default admin password); this is not a brute-force wordlist attack.


async def _snmp_get(host: str, community: str, oids: list[str], timeout: int = 5):
    dispatcher = SnmpDispatcher()
    try:
        var_binds_in = [ObjectType(ObjectIdentity(oid)) for oid in oids]
        error_indication, error_status, error_index, var_binds = await get_cmd(
            dispatcher,
            CommunityData(community, mpModel=1),  # mpModel=1 => SNMPv2c
            await UdpTransportTarget.create((host, 161), timeout=timeout, retries=0),
            *var_binds_in,
        )
        if error_indication:
            return None, str(error_indication)
        if error_status:
            return None, f"{error_status.prettyPrint()} at {error_index}"
        return [str(vb[1]) for vb in var_binds], None
    finally:
        dispatcher.transport_dispatcher.close_dispatcher()


def _run_async(coro):
    return asyncio.run(coro)


class SNMPv2cAdapter(Adapter):
    id = "snmp_v2c"
    display_name = "SNMP v1/v2c"
    platform_support = {"linux": True, "windows": True}

    def dependency_status(self) -> dict:
        if not _PYSNMP_AVAILABLE:
            return {
                "available": False,
                "detail": f"pysnmp not installed or failed to import: {_PYSNMP_IMPORT_ERROR}",
            }
        return {"available": True, "detail": ""}

    def list_operations(self) -> list[Operation]:
        return [
            Operation(
                id="snmp_identify",
                display_name="SNMP Identity (sysDescr/sysName/sysUpTime)",
                read_only=True,
                description="Queries standard SNMPv2-MIB system OIDs using the "
                            "'public' community string.",
                params=[OperationParam("community", "string", required=False,
                                        description="Community string, default 'public'")],
            ),
            Operation(
                id="snmp_printer_inventory",
                display_name="SNMP Printer Inventory",
                read_only=True,
                description="Queries Printer-MIB (RFC 3805) serial number and host "
                            "resources device description.",
                params=[OperationParam("community", "string", required=False,
                                        description="Community string, default 'public'")],
            ),
            Operation(
                id="snmp_default_community_check",
                display_name="Check for Vulnerabilities",
                read_only=True,
                description="Checks whether the well-known default read-only community "
                            "string 'public' is accepted — a single documented-default "
                            "check, not a brute-force attempt.",
            ),
        ]

    def run_operation(self, operation_id, resolved_ip, port, params, progress_cb=None, validate_cb=None) -> OperationResult:
        if not _PYSNMP_AVAILABLE:
            return OperationResult(
                status="unsupported",
                error_detail=f"pysnmp not available: {_PYSNMP_IMPORT_ERROR}",
            )

        community = params.get("community") or "public"

        if operation_id == "snmp_identify":
            oids = [_OIDS["sysDescr"], _OIDS["sysName"], _OIDS["sysUpTime"]]
            labels = ["sysDescr", "sysName", "sysUpTime"]
        elif operation_id == "snmp_printer_inventory":
            oids = [_OIDS["prtGeneralSerialNumber"], _OIDS["hrDeviceDescr"]]
            labels = ["serialNumber", "deviceDescr"]
        elif operation_id == "snmp_default_community_check":
            oids = [_OIDS["sysDescr"]]
            labels = ["sysDescr"]
            community = "public"
        else:
            return OperationResult(status="unsupported",
                                    error_detail=f"Unknown operation {operation_id}")

        if progress_cb:
            progress_cb(f"SNMP GET {labels} from {resolved_ip} (community={community!r})")

        try:
            values, error = _run_async(_snmp_get(resolved_ip, community, oids))
        except Exception as exc:  # pysnmp/asyncio errors, unreachable host, etc.
            return OperationResult(status="error", error_detail=str(exc))

        if error:
            # A timeout/no-response is a normal, expected outcome (device has
            # SNMP disabled or firewalled) — report as "ok" with an empty
            # finding, not as a job failure.
            return OperationResult(
                status="ok",
                summary="No SNMP response (service likely disabled/filtered)",
                evidence={"error": error},
            )

        evidence = dict(zip(labels, values))

        if operation_id == "snmp_default_community_check":
            return OperationResult(
                status="ok",
                severity="medium",
                summary="Default read-only community string 'public' is ACCEPTED",
                evidence=evidence,
                remediation="Disable the default 'public' community string or restrict "
                            "SNMP access via ACLs/firewall; use SNMPv3 with authentication "
                            "where supported.",
            )

        return OperationResult(
            status="ok",
            summary=f"{operation_id} completed",
            evidence=evidence,
        )
