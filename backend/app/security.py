"""
Target-scope validation, auth helpers, and secret encryption.
Implements the controls specified in 05-SECURITY-ARCHITECTURE.md.
This module is the ONLY place allowed to decide "is this target allowed" —
every adapter and the job runner must call validate_target() before
opening any connection. No other code path may open a socket/SSH session
directly to a device.
"""
import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet
from jose import jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .config import settings
from .db import AuthorizedNetwork

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Derive a stable Fernet key from the app secret so credentials can be
# decrypted across restarts without a separate key-management system.
# For production, operators should set a real, generated SECRET_KEY in .env
# — this is explicitly called out in README.md.
import base64
import hashlib

_fernet_key = base64.urlsafe_b64encode(
    hashlib.sha256(settings.secret_key.encode()).digest()
)
_fernet = Fernet(_fernet_key)


def encrypt_secret(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(subject: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    payload = {"sub": subject, "role": role, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


class ScopeError(Exception):
    """Raised whenever a target is outside the authorized scope. Every
    caller MUST surface this as a hard failure, never a silent skip."""


@dataclass
class ValidatedTarget:
    original: str
    resolved_ip: str
    authorized_network_id: int
    route_id: int | None


def resolve_and_validate(db: Session, host_or_ip: str) -> ValidatedTarget:
    """
    Resolve `host_or_ip` ONCE, check the resolved address against the
    explicit authorized_networks allow-list, and return the pinned
    address. Callers must connect to `.resolved_ip`, never re-resolve
    the original hostname again later — this is what closes the
    DNS-rebinding / TOCTOU window described in
    05-SECURITY-ARCHITECTURE.md §3.
    """
    try:
        # If it's already a literal IP, this succeeds without a DNS lookup.
        ip_obj = ipaddress.ip_address(host_or_ip)
        resolved_ip = str(ip_obj)
    except ValueError:
        try:
            # getaddrinfo instead of gethostbyname: works for both
            # IPv4 and IPv6, and we only ever take the first result,
            # which we then pin.
            infos = socket.getaddrinfo(host_or_ip, None)
        except socket.gaierror as exc:
            raise ScopeError(f"Could not resolve '{host_or_ip}': {exc}") from exc
        if not infos:
            raise ScopeError(f"No DNS results for '{host_or_ip}'")
        resolved_ip = infos[0][4][0]
        ip_obj = ipaddress.ip_address(resolved_ip)

    networks = db.query(AuthorizedNetwork).all()
    for net in networks:
        try:
            network = ipaddress.ip_network(net.cidr, strict=False)
        except ValueError:
            continue
        if ip_obj in network:
            return ValidatedTarget(
                original=host_or_ip,
                resolved_ip=resolved_ip,
                authorized_network_id=net.id,
                route_id=net.route_id,
            )

    raise ScopeError(
        f"'{host_or_ip}' (resolved {resolved_ip}) is not in any configured "
        f"authorized network. Add its CIDR under Settings before scanning it."
    )


ALLOWED_PORTS = {9100, 515, 631, 161, 162, 80, 443, 22, 3702, 5357}


def validate_port(port: int) -> None:
    if port not in ALLOWED_PORTS:
        raise ScopeError(
            f"Port {port} is not in the allowed destination port set "
            f"{sorted(ALLOWED_PORTS)}. Update ALLOWED_PORTS deliberately "
            f"if a new protocol adapter legitimately needs a new port."
        )
