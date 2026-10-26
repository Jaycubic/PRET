import pytest
from app.db import Device, AuthorizedNetwork, NetworkRoute
from app.security import encrypt_secret


def test_auth_login_success(client, admin_user):
    resp = client.post(
        "/api/auth/login",
        json={"username": "testadmin", "password": "adminpass123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["role"] == "admin"


def test_auth_login_failure(client, admin_user):
    resp = client.post(
        "/api/auth/login",
        json={"username": "testadmin", "password": "wrongpassword"},
    )
    assert resp.status_code == 401


def test_admin_vs_operator_authorization_boundaries(client, admin_token, operator_token):
    # Operator attempts to add authorized network -> 403 Forbidden
    op_resp = client.post(
        "/api/settings/networks",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={"cidr": "10.10.0.0/16", "description": "Illegal Subnet"},
    )
    assert op_resp.status_code == 403

    # Admin attempts to add authorized network -> 200 OK
    admin_resp = client.post(
        "/api/settings/networks",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"cidr": "10.10.0.0/16", "description": "Admin Added Subnet"},
    )
    assert admin_resp.status_code == 200
    net_id = admin_resp.json()["id"]

    # Delete network as admin -> 200 OK
    del_resp = client.delete(
        f"/api/settings/networks/{net_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "deleted"


def test_device_add_scope_enforcement(client, operator_token, authorized_network):
    # Target inside authorized_network (192.168.1.0/24) -> allowed
    resp_ok = client.post(
        "/api/devices",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={"ip_or_hostname": "192.168.1.55", "port": 9100},
    )
    assert resp_ok.status_code == 200
    dev_data = resp_ok.json()
    assert dev_data["ip_or_hostname"] == "192.168.1.55"

    # Target outside authorized_network (172.16.0.1) -> rejected with 403
    resp_bad = client.post(
        "/api/devices",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={"ip_or_hostname": "172.16.0.1", "port": 9100},
    )
    assert resp_bad.status_code == 403


def test_confirmation_gate_for_state_changing_operation(client, operator_token, db, authorized_network):
    # Create test device
    dev = Device(
        ip_or_hostname="192.168.1.60",
        resolved_ip="192.168.1.60",
        port=9100,
        status="unknown",
    )
    db.add(dev)
    db.commit()
    db.refresh(dev)

    # State-changing operation (pjl_fuzz_write_fs) without confirm=true -> 400
    resp_unconfirmed = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={
            "device_id": dev.id,
            "adapter_id": "pjl",
            "operation_id": "pjl_fuzz_write_fs",
            "confirm": False,
        },
    )
    assert resp_unconfirmed.status_code == 400
    assert "requires confirm=true" in resp_unconfirmed.json()["detail"]

    # Read-only operation without confirm=true -> allowed (200)
    resp_ro = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={
            "device_id": dev.id,
            "adapter_id": "pjl",
            "operation_id": "pjl_identify",
            "confirm": False,
        },
    )
    assert resp_ro.status_code == 200
    assert resp_ro.json()["status"] == "queued"


def test_investigate_cups_endpoint(client, operator_token, authorized_network):
    # Out of scope IP -> 403 Forbidden
    resp_blocked = client.post(
        "/api/devices/investigate-cups",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={"ip_or_hostname": "10.99.99.99", "port": 631},
    )
    assert resp_blocked.status_code == 403
    assert "not in any configured authorized network" in resp_blocked.json()["detail"].lower()

    # In scope IP -> 200 OK, returns registered device and audit findings
    resp_ok = client.post(
        "/api/devices/investigate-cups",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={"ip_or_hostname": "192.168.1.100", "port": 631},
    )
    assert resp_ok.status_code == 200
    data = resp_ok.json()
    assert "device" in data
    assert data["device"]["device_type"] == "print_server"
    assert data["device"]["port"] == 631
    assert "result" in data
    assert "risk_score" in data["result"]["evidence"]

    dev_id = data["device"]["id"]
    # Check device results endpoint
    results_resp = client.get(
        f"/api/devices/{dev_id}/results",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert results_resp.status_code == 200
    results_list = results_resp.json()
    assert len(results_list) >= 1
    assert results_list[0]["adapter_id"] == "cups_server"
    assert results_list[0]["operation_id"] == "cups_full_audit"

