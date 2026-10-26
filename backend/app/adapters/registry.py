"""
Fixed, explicit adapter registry. Deliberately NOT dynamic plugin
auto-discovery from a directory — see 06-PROTOCOL-ADAPTER-DESIGN.md
("Registration, versioning, testing") for why that would reopen the
exact "arbitrary code" concern this design closes off.

SNMP / IPP / mDNS / HTTP(S) adapters are stubbed per 09-ROADMAP.md's
phased plan (Phase 2) — they register so the catalog/UI shape is already
correct, but report dependency_status(available=False) with a clear
"not yet implemented" message rather than silently doing nothing.
"""
from .base import Adapter, Operation
from .pjl import PJLAdapter
from .pcl import PCLAdapter
from .postscript import PostScriptAdapter
from .mdns import MDNSAdapter
from .snmp_v2c import SNMPv2cAdapter
from .snmp_v3 import SNMPv3Adapter
from .ipp import IPPAdapter
from .cups_server import CUPSServerAdapter
from .http_fingerprint import HTTPFingerprintAdapter
from .wsd import WSDAdapter


class _StubAdapter(Adapter):
    def __init__(self, id_, name):
        self.id = id_
        self.display_name = name

    def dependency_status(self) -> dict:
        return {"available": False, "detail": "Not yet implemented."}

    def list_operations(self) -> list[Operation]:
        return []

    def run_operation(self, *a, **kw):
        from .base import OperationResult
        return OperationResult(status="unsupported", error_detail="Adapter not implemented yet.")


ADAPTERS: dict[str, Adapter] = {
    a.id: a for a in [
        PJLAdapter(),
        PCLAdapter(),
        PostScriptAdapter(),
        SNMPv2cAdapter(),
        SNMPv3Adapter(),
        MDNSAdapter(),
        IPPAdapter(),
        CUPSServerAdapter(),
        HTTPFingerprintAdapter(),
        WSDAdapter(),
    ]
}


def get_adapter(adapter_id: str) -> Adapter | None:
    return ADAPTERS.get(adapter_id)
