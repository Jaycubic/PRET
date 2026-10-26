"""
PostScript adapter — same subprocess pattern as PJL/PCL.

Deliberate scope decision for this session: PostScript in upstream PRET
also exposes do_format/do_destroy/do_hang/do_restart/do_reset/do_overlay
— genuinely destructive or disruptive operations (do_destroy explicitly
overwrites disk data; do_format wipes the filesystem; do_hang can crash
the device's interpreter). Consistent with the exclusion of PRET's
print/edit commands in 02-INTEGRATION-STRATEGY.md, these are NOT exposed
in this adapter at all — not even gated behind confirmation — because
there's no assessment value that offsets "can irreversibly destroy a
real device" for a v1 catalog. If a future session wants to add a
*detection* for whether these commands are reachable (e.g. "is 'destroy'
present in this interpreter's command table") that's a different,
read-only, much lower-risk operation than actually invoking them — worth
discussing explicitly before building, per 05-SECURITY-ARCHITECTURE.md
§11's "features disabled by default until further hardened" pattern.

This adapter therefore only covers genuinely read-only inventory,
confirmed against the actual do_* methods in pret/postscript.py.
"""
from __future__ import annotations

import re

from .base import Adapter, Operation, OperationParam, OperationResult
from .pret_runner import run_pret_session

_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9 ._\-/\\:]{1,256}$")


def _validate_device_path(path: str) -> str:
    if ".." in path or not _SAFE_PATH_RE.match(path):
        raise ValueError(f"Rejected unsafe path parameter: {path!r}")
    return path


_OPERATIONS = [
    Operation(
        id="ps_identify",
        display_name="Get Device Info",
        read_only=True,
        description="Query PostScript identity and interpreter version (id, version).",
    ),
    Operation(
        id="ps_dir_list",
        display_name="List Filesystem",
        read_only=True,
        description="List files on the device's filesystem (ls).",
        params=[OperationParam("path", "path", required=False,
                                description="Device path, default root")],
    ),
    Operation(
        id="ps_disk_free",
        display_name="Check Disk/Memory",
        read_only=True,
        description="Query free disk space and memory (df, free).",
    ),
    Operation(
        id="ps_inventory",
        display_name="Device Inventory",
        read_only=True,
        description="Query uptime, current date, and page count (uptime, date, pagecount).",
    ),
    Operation(
        id="ps_list_devices",
        display_name="List PostScript Devices",
        read_only=True,
        description="List configured I/O devices known to the interpreter ('devices').",
    ),
]

_TEMPLATES = {
    "ps_identify": "id\nversion\n",
    "ps_dir_list": "ls {path}\n",
    "ps_disk_free": "df\nfree\n",
    "ps_inventory": "uptime\ndate\npagecount\n",
    "ps_list_devices": "devices\n",
}


class PostScriptAdapter(Adapter):
    id = "postscript"
    display_name = "PostScript"
    platform_support = {"linux": True, "windows": True}

    def dependency_status(self) -> dict:
        from ..config import settings
        pret_py = settings.pret_dir / "pret.py"
        if not pret_py.exists():
            return {"available": False, "detail": f"pret.py not found at {pret_py}"}
        return {"available": True, "detail": ""}

    def list_operations(self) -> list[Operation]:
        return _OPERATIONS

    def run_operation(self, operation_id, resolved_ip, port, params, progress_cb=None, validate_cb=None) -> OperationResult:
        if operation_id not in _TEMPLATES:
            return OperationResult(status="unsupported",
                                    error_detail=f"Unknown operation {operation_id}")

        template = _TEMPLATES[operation_id]
        if "{path}" in template:
            raw_path = params.get("path", "")
            try:
                safe_path = _validate_device_path(raw_path) if raw_path else ""
            except ValueError as exc:
                return OperationResult(status="error", error_detail=str(exc))
            command_text = template.format(path=safe_path)
        else:
            command_text = template

        returncode, raw_output, error = run_pret_session(
            "ps", resolved_ip, port, command_text, progress_cb
        )
        if error is not None:
            status = "timeout" if "timeout" in error.lower() else "error"
            return OperationResult(status=status, error_detail=error)

        capped = raw_output[-16000:]
        status = "ok" if returncode == 0 else "error"
        return OperationResult(
            status=status,
            summary=f"{operation_id} completed (exit {returncode})",
            evidence={"output": capped, "truncated": len(raw_output) > len(capped)},
            error_detail="" if status == "ok" else capped[-2000:],
        )
