"""
mDNS / DNS-SD discovery adapter — real implementation using the actively
maintained, pure-Python `zeroconf` library (confirmed maintained in
pret-web-ui-docs/03-PROTOCOL-EXPANSION.md). Covers what's colloquially
called "Bonjour" — Apple's trade name for the same mDNS/DNS-SD standard,
per the clarification in 12-MASTER-BUILD-PLAN.md §2.

This is a discovery adapter, not a per-target operation: detect() browses
the LAN for a fixed time window and returns found services, rather than
querying one already-known target. The job runner's "device_id" concept
doesn't quite fit a network-wide browse, so this is exposed via its own
discovery entry point (see routes/discovery.py) rather than run_operation()
against a single device — list_operations() still returns a catalog entry
for UI/catalog consistency, but it's handled specially by the route.
"""
from __future__ import annotations

import time

from .base import Adapter, Operation, OperationResult

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    _ZEROCONF_AVAILABLE = True
    _ZEROCONF_IMPORT_ERROR = ""
except ImportError as exc:
    _ZEROCONF_AVAILABLE = False
    _ZEROCONF_IMPORT_ERROR = str(exc)
    ServiceListener = object  # type: ignore

# The service types that matter for printer discovery.
PRINTER_SERVICE_TYPES = [
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",  # raw/JetDirect port 9100 advertisement
]


def browse_for_printers(timeout_seconds: int = 5) -> list[dict]:
    """
    Browses the LAN for printer-related mDNS/DNS-SD services for
    `timeout_seconds`, then returns what was found. This is explicitly
    time-boxed and the Zeroconf instance is closed deterministically on
    the way out — see 07-DATA-MODEL-AND-MEMORY.md §5 on not leaving
    discovery listeners running past their requested window.
    """
    if not _ZEROCONF_AVAILABLE:
        raise RuntimeError(f"zeroconf not available: {_ZEROCONF_IMPORT_ERROR}")

    found: dict[str, dict] = {}

    class _Listener(ServiceListener):
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name, timeout=2000)
            if info is None:
                return
            addresses = info.parsed_scoped_addresses()
            found[name] = {
                "name": name,
                "type": type_,
                "addresses": addresses,
                "port": info.port,
                "server": info.server,
                "properties": {
                    (k.decode() if isinstance(k, bytes) else k):
                    (v.decode(errors="replace") if isinstance(v, bytes) else v)
                    for k, v in (info.properties or {}).items()
                },
            }

        def update_service(self, zc, type_, name):
            self.add_service(zc, type_, name)

        def remove_service(self, zc, type_, name):
            found.pop(name, None)

    zc = Zeroconf()
    try:
        listener = _Listener()
        browsers = [
            ServiceBrowser(zc, st, listener) for st in PRINTER_SERVICE_TYPES
        ]
        time.sleep(timeout_seconds)
    finally:
        zc.close()  # deterministic teardown — no lingering listener/socket

    return list(found.values())


class MDNSAdapter(Adapter):
    id = "mdns"
    display_name = "mDNS / DNS-SD Discovery (Bonjour)"
    platform_support = {"linux": True, "windows": True}

    def dependency_status(self) -> dict:
        if not _ZEROCONF_AVAILABLE:
            return {"available": False, "detail": f"zeroconf not installed: {_ZEROCONF_IMPORT_ERROR}"}
        return {"available": True, "detail": ""}

    def list_operations(self) -> list[Operation]:
        return [
            Operation(
                id="mdns_discover",
                display_name="Discover Printers (mDNS/Bonjour)",
                read_only=True,
                description="Browses the LAN for _ipp._tcp, _ipps._tcp, _printer._tcp, "
                            "and _pdl-datastream._tcp services for a few seconds.",
            ),
        ]

    def run_operation(self, operation_id, resolved_ip, port, params, progress_cb=None, validate_cb=None) -> OperationResult:
        if operation_id != "mdns_discover":
            return OperationResult(status="unsupported", error_detail=f"Unknown operation {operation_id}")
        if progress_cb:
            progress_cb("Browsing LAN for mDNS/DNS-SD printer services...")
        try:
            results = browse_for_printers(timeout_seconds=5)
        except Exception as exc:
            return OperationResult(status="error", error_detail=str(exc))
        return OperationResult(
            status="ok",
            summary=f"Found {len(results)} printer-related mDNS service(s)",
            evidence={"services": results},
        )
