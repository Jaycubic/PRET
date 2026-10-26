"""
Shared subprocess runner for all PRET-language adapters (PJL/PCL/
PostScript). Extracted from the original PJL-only implementation once a
second and third adapter needed the identical pattern — see
pret-web-ui-docs/02-INTEGRATION-STRATEGY.md Path A.

This is the ONLY place that actually invokes `pret.py`. Every language
adapter calls run_pret_session() with its own fixed command template —
none of them builds a subprocess call directly, which keeps the "no
general-purpose shell" guarantee in one auditable place.
"""
from __future__ import annotations

import queue
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

from ..config import settings


def run_pret_session(
    mode: str,
    resolved_ip: str,
    port: int,
    command_text: str,
    progress_cb: Optional[callable] = None,
) -> tuple[int | None, str, str | None]:
    """
    Runs `pret.py <ip>:<port> <mode> -q -i <cmdfile>` as a subprocess,
    streaming output to progress_cb as it arrives.

    Deliberately does NOT pass PRET's own `-o <logfile>` flag. Found
    during Session B testing: upstream PRET's printer.py opens that
    logfile in binary mode but for ps/pcl modes writes a `str` session
    header to it, raising TypeError and crashing the subprocess before
    it reaches the command loop. PJL has no header branch so never hits
    it. We don't read that logfile anyway (all evidence comes from
    captured stdout), so the fix is to not ask PRET to open it, rather
    than patch vendored source. Tracked in 12-MASTER-BUILD-PLAN.md.

    TIMEOUT IMPLEMENTATION NOTE (also found during Session B testing):
    proc.stdout.readline() is a BLOCKING call. If the subprocess goes
    silent — exactly what happens when PRET is stuck waiting on a
    network read against an unresponsive/misbehaving device — a naive
    "read a line, else sleep and recheck the deadline" loop never gets a
    chance to recheck the deadline, because it's blocked inside
    readline() itself. The fix is a dedicated reader thread feeding a
    Queue, with the main loop enforcing the deadline via
    queue.get(timeout=...) instead of a blocking read. This is what
    actually guarantees settings.job_timeout_seconds is honored even
    when the target never responds — the exact scenario
    05-SECURITY-ARCHITECTURE.md §5 requires timeouts for.
    """
    with tempfile.TemporaryDirectory(dir=settings.job_tmp_dir) as job_dir:
        job_dir = Path(job_dir)
        cmdfile = job_dir / "commands.txt"
        cmdfile.write_text(command_text)

        target = f"{resolved_ip}:{port}"
        import sys
        cmd = [
            sys.executable, str(settings.pret_dir / "pret.py"),
            target, mode,
            "-q",
            "-i", str(cmdfile),
        ]

        if progress_cb:
            progress_cb(f"Launching: {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(settings.pret_dir),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            return None, "", str(exc)

        line_queue: "queue.Queue[str | None]" = queue.Queue()

        def _reader() -> None:
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    line_queue.put(line)
            except Exception:
                pass
            finally:
                line_queue.put(None)  # EOF sentinel

        reader_thread = threading.Thread(target=_reader, daemon=True)
        reader_thread.start()

        start = time.time()
        stdout_lines: list[str] = []
        timed_out = False

        while True:
            remaining = settings.job_timeout_seconds - (time.time() - start)
            if remaining <= 0:
                timed_out = True
                break
            try:
                line = line_queue.get(timeout=min(remaining, 1.0))
            except queue.Empty:
                continue  # re-check the deadline; this is what makes the
                          # timeout actually fire even with a silent process
            if line is None:
                break  # subprocess closed stdout — it's finishing up
            stdout_lines.append(line)
            if progress_cb:
                progress_cb(line.rstrip())

        if timed_out:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            return None, "".join(stdout_lines), (
                f"Exceeded {settings.job_timeout_seconds}s wall-clock timeout "
                f"(target unresponsive or hung)"
            )

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

        return proc.returncode, "".join(stdout_lines), None
