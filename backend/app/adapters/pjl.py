"""
PJL adapter: drives upstream PRET (pret.py) unmodified, as a subprocess,
via its existing -i/-q/-o non-interactive flags.
Implements Path A from 02-INTEGRATION-STRATEGY.md.

The browser never sends a raw PRET command. Every operation below maps to
a FIXED command template; run_operation() only ever substitutes validated
parameters into that fixed template, never arbitrary user text — this is
the concrete mechanism behind 05-SECURITY-ARCHITECTURE.md §10.
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
        id="pjl_identify",
        display_name="Get Device Info",
        read_only=True,
        description="Query PJL identity (id) and default variables (info config).",
    ),
    Operation(
        id="pjl_list_variables",
        display_name="List PJL Variables",
        read_only=True,
        description="Dump all readable PJL environment variables (info variables).",
    ),
    Operation(
        id="pjl_dir_list",
        display_name="List Filesystem Root",
        read_only=True,
        description="List files on the device's PJL filesystem (ls).",
        params=[OperationParam("path", "path", required=False,
                                description="Device path, default '0:\\'")],
    ),
    Operation(
        id="pjl_check_default_creds",
        display_name="Check for Vulnerabilities",
        read_only=True,
        description="Checks for an unset/default PJL disk lock PIN (lock status only, "
                     "does not attempt to change it).",
    ),
    Operation(
        id="pjl_fuzz_write_fs",
        display_name="Fuzz Write Test (state-changing)",
        read_only=False,
        description="Runs PRET's filesystem write-fuzzing routine. Can create files "
                     "on the device. Requires explicit confirmation.",
    ),
]

_TEMPLATES = {
    "pjl_identify": "id\ninfo config\n",
    "pjl_list_variables": "info variables\n",
    "pjl_dir_list": "ls {path}\n",
    "pjl_check_default_creds": "lock status\n",
    "pjl_fuzz_write_fs": "fuzz write\n",
}


class PJLAdapter(Adapter):
    id = "pjl"
    display_name = "PJL"
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
            raw_path = params.get("path", "0:\\")
            try:
                safe_path = _validate_device_path(raw_path)
            except ValueError as exc:
                return OperationResult(status="error", error_detail=str(exc))
            command_text = template.format(path=safe_path)
        else:
            command_text = template

        returncode, raw_output, error = run_pret_session(
            "pjl", resolved_ip, port, command_text, progress_cb
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
