"""
SSH local-port-forward tunnel manager.
Implements 10-NETWORK-TUNNEL-ARCHITECTURE.md's default mechanism: open a
job-scoped local forward through a pivot host, hand the adapter
0.0.0.0:<local_port> instead of the real target, close the forward when
the job ends. No changes to PRET itself are required for this to work.
"""
from __future__ import annotations

import select
import socket
import threading
from dataclasses import dataclass

import paramiko

from .db import NetworkRoute
from .security import decrypt_secret


@dataclass
class ActiveForward:
    local_port: int
    _transport: paramiko.Transport
    _client: paramiko.SSHClient
    _stop_event: threading.Event
    _thread: threading.Thread

    def close(self) -> None:
        self._stop_event.set()
        try:
            self._client.close()
        except Exception:
            pass


def _forward_handler(channel, remote_sock):
    """Pump bytes between the local accepted socket and the SSH channel."""
    while True:
        r, _, _ = select.select([channel, remote_sock], [], [], 1.0)
        if channel in r:
            data = channel.recv(4096)
            if not data:
                break
            remote_sock.sendall(data)
        if remote_sock in r:
            data = remote_sock.recv(4096)
            if not data:
                break
            channel.sendall(data)
    channel.close()
    remote_sock.close()


def open_local_forward(
    route: NetworkRoute, remote_host: str, remote_port: int
) -> ActiveForward:
    """
    Open an SSH session to the pivot host and a local listening socket
    that forwards accepted connections to remote_host:remote_port on the
    far side of that SSH session. Caller is responsible for calling
    .close() when the job is done — see job runner's finally block.
    """
    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
    except Exception:
        pass
    from .config import settings
    if getattr(settings, "test_mode", False):
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    # NOTE: RejectPolicy means the pivot host's key must already be
    # trusted (e.g. in the service account's known_hosts) before this
    # will connect. This is intentional — silently trusting unknown
    # pivot host keys would defeat the point of pinning a named,
    # admin-configured route. See README.md "First-time pivot setup".

    secret = decrypt_secret(route.credential_encrypted)
    connect_kwargs = dict(
        hostname=route.pivot_host,
        port=route.pivot_port,
        username=route.pivot_username,
        timeout=10,
    )
    if route.credential_kind == "ssh_key":
        import io
        pkey = paramiko.RSAKey.from_private_key(io.StringIO(secret))
        connect_kwargs["pkey"] = pkey
    else:
        connect_kwargs["password"] = secret

    client.connect(**connect_kwargs)
    transport = client.get_transport()

    local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_sock.bind(("0.0.0.0", 0))
    local_sock.listen(1)
    local_port = local_sock.getsockname()[1]

    stop_event = threading.Event()

    def accept_loop():
        local_sock.settimeout(1.0)
        while not stop_event.is_set():
            try:
                client_sock, _ = local_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                channel = transport.open_channel(
                    "direct-tcpip",
                    (remote_host, remote_port),
                    client_sock.getsockname(),
                )
            except Exception:
                client_sock.close()
                continue
            t = threading.Thread(
                target=_forward_handler, args=(channel, client_sock), daemon=True
            )
            t.start()
        local_sock.close()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()

    return ActiveForward(
        local_port=local_port,
        _transport=transport,
        _client=client,
        _stop_event=stop_event,
        _thread=thread,
    )
