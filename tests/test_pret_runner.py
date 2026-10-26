import socket
import threading
import time
import pytest
from app.adapters.pret_runner import run_pret_session
from app.config import settings


def _run_mock_pjl_printer(stop_event, port_holder):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 0))
    sock.listen(1)
    port_holder["port"] = sock.getsockname()[1]
    sock.settimeout(0.5)

    while not stop_event.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        conn.settimeout(1.0)
        try:
            data = conn.recv(1024)
            # Reply with PJL device ID signature
            response = b'@PJL INFO ID\r\n"HP LaserJet Test Fixture"\r\n\x0c'
            conn.sendall(response)
        except Exception:
            pass
        finally:
            conn.close()

    sock.close()


def test_pret_runner_with_mock_printer():
    stop_event = threading.Event()
    port_holder = {}
    server_thread = threading.Thread(
        target=_run_mock_pjl_printer, args=(stop_event, port_holder), daemon=True
    )
    server_thread.start()

    # Wait for server to bind
    for _ in range(50):
        if "port" in port_holder:
            break
        time.sleep(0.05)

    port = port_holder["port"]
    lines = []

    try:
        returncode, raw_output, error = run_pret_session(
            mode="pjl",
            resolved_ip="0.0.0.0",
            port=port,
            command_text="id\n",
            progress_cb=lambda l: lines.append(l),
        )
        assert error is None or "timeout" not in error.lower()
        # Subprocess finished
        assert isinstance(raw_output, str)
    finally:
        stop_event.set()
        server_thread.join(timeout=1.0)


def test_pret_runner_hang_timeout():
    # Mock server that accepts connection and never replies
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    stop_event = threading.Event()

    def hung_server():
        sock.settimeout(0.5)
        while not stop_event.is_set():
            try:
                conn, _ = sock.accept()
                while not stop_event.is_set():
                    time.sleep(0.1)
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break
        sock.close()

    thread = threading.Thread(target=hung_server, daemon=True)
    thread.start()

    # Temporarily set short timeout in settings for fast test
    orig_timeout = settings.job_timeout_seconds
    settings.job_timeout_seconds = 2

    try:
        t0 = time.time()
        returncode, raw_output, error = run_pret_session(
            mode="pjl",
            resolved_ip="0.0.0.0",
            port=port,
            command_text="id\n",
        )
        elapsed = time.time() - t0
        # Should timeout around 2 seconds and not hang indefinitely
        assert elapsed < 10
        assert error is not None and "timeout" in error.lower()
    finally:
        settings.job_timeout_seconds = orig_timeout
        stop_event.set()
        thread.join(timeout=1.0)
