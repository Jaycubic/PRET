import pytest
from app.db import AuthorizedNetwork
from app.security import (
    resolve_and_validate,
    validate_port,
    encrypt_secret,
    decrypt_secret,
    hash_password,
    verify_password,
    ScopeError,
)


def test_password_hashing():
    pw = "SuperSecret123!"
    hashed = hash_password(pw)
    assert hashed != pw
    assert verify_password(pw, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_secret_encryption_roundtrip():
    secret = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."
    encrypted = encrypt_secret(secret)
    assert encrypted != secret
    decrypted = decrypt_secret(encrypted)
    assert decrypted == secret


def test_port_validation():
    # Valid allowed ports
    validate_port(80)
    validate_port(9100)
    validate_port(5357)

    # Disallowed/out-of-range ports
    with pytest.raises(ScopeError):
        validate_port(0)
    with pytest.raises(ScopeError):
        validate_port(-1)
    with pytest.raises(ScopeError):
        validate_port(70000)
    with pytest.raises(ScopeError):
        validate_port(65535)  # Not in ALLOWED_PORTS



def test_scope_validation_in_scope_ipv4(db, authorized_network):
    # 192.168.1.0/24 is authorized
    validated = resolve_and_validate(db, "192.168.1.50")
    assert validated.resolved_ip == "192.168.1.50"
    assert validated.route_id is None


def test_scope_validation_out_of_scope_ipv4(db, authorized_network):
    # 192.168.2.50 is NOT in 192.168.1.0/24
    with pytest.raises(ScopeError) as excinfo:
        resolve_and_validate(db, "192.168.2.50")
    assert "not in any configured authorized network" in str(excinfo.value)



def test_scope_validation_boundary_addresses(db, authorized_network):
    # Network and broadcast addresses in 192.168.1.0/24
    validated = resolve_and_validate(db, "192.168.1.1")
    assert validated.resolved_ip == "192.168.1.1"

    validated_end = resolve_and_validate(db, "192.168.1.254")
    assert validated_end.resolved_ip == "192.168.1.254"

    # Just outside the boundary: 192.168.0.255, 192.168.2.0
    with pytest.raises(ScopeError):
        resolve_and_validate(db, "192.168.0.255")
    with pytest.raises(ScopeError):
        resolve_and_validate(db, "192.168.2.0")


def test_scope_validation_disallowed_loopback_and_metadata(db, authorized_network):
    # Loopback and cloud metadata targets should be rejected if not in authorized_networks
    with pytest.raises(ScopeError):
        resolve_and_validate(db, "0.0.0.0")
    with pytest.raises(ScopeError):
        resolve_and_validate(db, "169.254.169.254")


def test_scope_validation_with_route_id(db):
    from app.db import NetworkRoute
    route = NetworkRoute(
        name="Pivot-Lab",
        pivot_host="192.168.1.10",
        pivot_port=22,
        pivot_username="pivotuser",
        credential_encrypted=encrypt_secret("testpass"),
        credential_kind="password",
        is_enabled=True,
    )
    db.add(route)
    db.commit()
    db.refresh(route)

    remote_net = AuthorizedNetwork(cidr="10.0.50.0/24", description="Remote Isolated Subnet", route_id=route.id)
    db.add(remote_net)
    db.commit()

    validated = resolve_and_validate(db, "10.0.50.15")
    assert validated.resolved_ip == "10.0.50.15"
    assert validated.route_id == route.id
