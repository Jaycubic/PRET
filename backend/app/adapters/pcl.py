"""
PCL adapter — same subprocess pattern as PJL, grounded in PCL's ACTUAL
command set as found in pret/pcl.py (do_ls, do_info, do_free, do_selftest
— confirmed by reading the file, not assumed). PCL has a much smaller
command surface than PJL/PostScript in upstream PRET.
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
        id="pcl_list_fonts",
        display_name="List Installed Fonts",
        read_only=True,
        description="Query installed fonts via PCL 'info fonts'.",
    ),
    Operation(
        id="pcl_list_macros",
        display_name="List Macros",
        read_only=True,
        description="Query stored macros via PCL 'info macros'.",
    ),
    Operation(
        id="pcl_free_memory",
        display_name="Check Available Memory",
        read_only=True,
        description="Query available printer memory ('free').",
    ),
    Operation(
        id="pcl_dir_list",
        display_name="List Filesystem",
        read_only=True,
        description="List files on the device's filesystem (ls).",
        params=[OperationParam("path", "path", required=False,
                                description="Device path, default root")],
    ),
    Operation(
        id="pcl_selftest",
        display_name="Run Self-Test (prints a physical page)",
        read_only=False,
        description="Triggers PRET's PCL self-test ('selftest'). This causes the "
                     "physical device to print a test page — real paper/toner cost, "
                     "not just a data-level change. Requires explicit confirmation "
                     "for that reason even though it doesn't alter stored device state.",
    ),
]

_TEMPLATES = {
    "pcl_list_fonts": "info fonts\n",
    "pcl_list_macros": "info macros\n",
    "pcl_free_memory": "free\n",
    "pcl_dir_list": "ls {path}\n",
    "pcl_selftest": "selftest\n",
}


class PCLAdapter(Adapter):
    id = "pcl"
    display_name = "PCL"
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
            "pcl", resolved_ip, port, command_text, progress_cb
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
