"""
Common adapter interface. See 06-PROTOCOL-ADAPTER-DESIGN.md.
Every protocol module (PJL now; SNMP/IPP/mDNS/HTTP planned per
09-ROADMAP.md) implements this shape. The job runner and the
/api/adapters endpoint only ever talk to adapters through this interface
— neither one has any protocol-specific knowledge.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class OperationParam:
    name: str
    type: str  # "string" | "int" | "path"
    required: bool = True
    description: str = ""


@dataclass
class Operation:
    id: str
    display_name: str
    read_only: bool
    description: str = ""
    params: list[OperationParam] = field(default_factory=list)


@dataclass
class OperationResult:
    status: str  # ok | error | timeout | unsupported
    severity: str = "info"
    summary: str = ""
    evidence: dict | None = None
    remediation: str = ""
    error_detail: str = ""


ProgressCallback = Callable[[str], None]

# Called by an adapter with a NEWLY-DISCOVERED host (e.g. a redirect
# Location header) that was not the job's original validated target.
# Raises security.ScopeError if out of scope; returns a ValidatedTarget
# (resolved_ip, etc.) if allowed. This is what makes redirect
# revalidation (05-SECURITY-ARCHITECTURE.md §4) possible without every
# adapter importing the DB layer directly — the job runner supplies the
# real implementation (closed over its own db session) at call time.
ValidateCallback = Callable[[str], Any]


class Adapter:
    id: str = "base"
    display_name: str = "Base Adapter"
    platform_support: dict = {"linux": True, "windows": True}

    def dependency_status(self) -> dict:
        """Return {'available': bool, 'detail': str}. Mirrors the real
        silent-degradation risk found in upstream PRET's discovery.py —
        this adapter layer must surface it instead of hiding it."""
        return {"available": True, "detail": ""}

    def list_operations(self) -> list[Operation]:
        raise NotImplementedError

    def run_operation(
        self,
        operation_id: str,
        resolved_ip: str,
        port: int,
        params: dict,
        progress_cb: Optional[ProgressCallback] = None,
        validate_cb: Optional[ValidateCallback] = None,
    ) -> OperationResult:
        raise NotImplementedError
