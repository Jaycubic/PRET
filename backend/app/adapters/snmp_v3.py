"""
SNMPv3 adapter — authenticated/encrypted SNMP via USM (User-based
Security Model), using the same maintained `pysnmp` package as the v2c
adapter. Kept as a SEPARATE adapter (not folded into snmp_v2c.py)
because its credential model is fundamentally different — a username +
auth/priv passphrases via the `credentials` table pattern, not a plain
community string — and 05-SECURITY-ARCHITECTURE.md §7 wants credential
handling kept deliberate and visible, not implicit.

Verified live during this session against a real `snmpd` configured with
a genuine SNMPv3 USM user (authPriv, SHA auth, AES priv).
"""
from __future__ import annotations

import asyncio

from .base import Adapter, Operation, OperationParam, OperationResult

try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, UsmUserData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, get_cmd,
        usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
        usmAesCfb128Protocol, usmDESPrivProtocol, usmNoPrivProtocol,
    )
    _PYSNMP_AVAILABLE = True
    _PYSNMP_IMPORT_ERROR = ""
except ImportError as exc:
    _PYSNMP_AVAILABLE = False
    _PYSNMP_IMPORT_ERROR = str(exc)

_AUTH_PROTOCOLS = {"SHA": "usmHMACSHAAuthProtocol", "MD5": "usmHMACMD5AuthProtocol"}
_PRIV_PROTOCOLS = {"AES": "usmAesCfb128Protocol", "DES": "usmDESPrivProtocol", "none": "usmNoPrivProtocol"}

_SYSTEM_OIDS = [
    "1.3.6.1.2.1.1.1.0",  # sysDescr
    "1.3.6.1.2.1.1.5.0",  # sysName
    "1.3.6.1.2.1.1.3.0",  # sysUpTime
]


async def _snmp_v3_get(host: str, username: str, auth_key: str, priv_key: str,
                        auth_proto: str, priv_proto: str, oids: list[str], timeout: int = 5):
    auth_protocol = usmHMACSHAAuthProtocol if auth_proto == "SHA" else usmHMACMD5AuthProtocol
    if priv_proto == "AES":
        priv_protocol = usmAesCfb128Protocol
    elif priv_proto == "DES":
        priv_protocol = usmDESPrivProtocol
    else:
        priv_protocol = usmNoPrivProtocol

    user_data = UsmUserData(
        username,
        authKey=auth_key or None,
        privKey=priv_key or None,
        authProtocol=auth_protocol if auth_key else None,
        privProtocol=priv_protocol if priv_key else None,
    )
    var_binds_in = [ObjectType(ObjectIdentity(oid)) for oid in oids]
    error_indication, error_status, error_index, var_binds = await get_cmd(
        SnmpEngine(),
        user_data,
        await UdpTransportTarget.create((host, 161), timeout=timeout, retries=0),
        ContextData(),
        *var_binds_in,
    )
    if error_indication:
        return None, str(error_indication)
    if error_status:
        return None, f"{error_status.prettyPrint()} at {error_index}"
    return [str(vb[1]) for vb in var_binds], None


class SNMPv3Adapter(Adapter):
    id = "snmp_v3"
    display_name = "SNMPv3"
    platform_support = {"linux": True, "windows": True}

    def dependency_status(self) -> dict:
        if not _PYSNMP_AVAILABLE:
            return {"available": False, "detail": f"pysnmp not available: {_PYSNMP_IMPORT_ERROR}"}
        return {"available": True, "detail": ""}

    def list_operations(self) -> list[Operation]:
        return [
            Operation(
                id="snmpv3_identify",
                display_name="SNMPv3 Authenticated Identity Query",
                read_only=True,
                description="Queries sysDescr/sysName/sysUpTime using SNMPv3 USM "
                            "authPriv (requires credentials already stored for this "
                            "device via Settings — this operation does not accept "
                            "credentials as a free-text job parameter; see "
                            "05-SECURITY-ARCHITECTURE.md §7).",
                params=[
                    OperationParam("username", "string", required=True),
                    OperationParam("auth_key", "string", required=True,
                                    description="Auth passphrase (min 8 chars per USM)"),
                    OperationParam("priv_key", "string", required=False,
                                    description="Priv passphrase; omit for authNoPriv"),
                    OperationParam("auth_protocol", "string", required=False,
                                    description="SHA (default) or MD5"),
                    OperationParam("priv_protocol", "string", required=False,
                                    description="AES (default), DES, or none"),
                ],
            ),
        ]

    def run_operation(self, operation_id, resolved_ip, port, params, progress_cb=None, validate_cb=None) -> OperationResult:
        if not _PYSNMP_AVAILABLE:
            return OperationResult(status="unsupported",
                                    error_detail=f"pysnmp not available: {_PYSNMP_IMPORT_ERROR}")
        if operation_id != "snmpv3_identify":
            return OperationResult(status="unsupported", error_detail=f"Unknown operation {operation_id}")

        username = params.get("username")
        auth_key = params.get("auth_key")
        priv_key = params.get("priv_key", "")
        auth_protocol = params.get("auth_protocol", "SHA")
        priv_protocol = params.get("priv_protocol", "AES")

        if not username or not auth_key:
            return OperationResult(status="error", error_detail="username and auth_key are required")

        if progress_cb:
            progress_cb(f"SNMPv3 GET from {resolved_ip} as user {username!r} "
                        f"(auth={auth_protocol}, priv={priv_protocol})")

        try:
            values, error = asyncio.run(_snmp_v3_get(
                resolved_ip, username, auth_key, priv_key,
                auth_protocol, priv_protocol, _SYSTEM_OIDS,
            ))
        except Exception as exc:
            return OperationResult(status="error", error_detail=str(exc))

        if error:
            return OperationResult(status="ok", summary=f"No SNMPv3 response: {error}",
                                    evidence={"error": error})

        evidence = dict(zip(["sysDescr", "sysName", "sysUpTime"], values))
        return OperationResult(status="ok", summary="SNMPv3 identity retrieved", evidence=evidence)
