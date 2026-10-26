"""
Admin-only settings: authorized network allow-list and tunnel routes.
This is where 05-SECURITY-ARCHITECTURE.md §1's "explicit, admin-editable,
audit-logged" scope configuration lives.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db, AuthorizedNetwork, NetworkRoute, AuditLog, User
from ..deps import require_admin
from ..schemas import AuthorizedNetworkCreate, NetworkRouteCreate
from ..security import encrypt_secret

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/networks")
def list_networks(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    networks = db.query(AuthorizedNetwork).all()
    return [
        {"id": n.id, "cidr": n.cidr, "description": n.description, "route_id": n.route_id}
        for n in networks
    ]


@router.post("/networks")
def add_network(body: AuthorizedNetworkCreate, db: Session = Depends(get_db),
                 user: User = Depends(require_admin)):
    net = AuthorizedNetwork(cidr=body.cidr, description=body.description, route_id=body.route_id)
    db.add(net)
    db.commit()
    db.refresh(net)
    net_id = net.id
    cidr = net.cidr
    desc = net.description
    r_id = net.route_id
    db.add(AuditLog(user_id=user.id, action="add_authorized_network",
                     outcome="success", detail=body.cidr))
    db.commit()
    return {"id": net_id, "cidr": cidr, "description": desc, "route_id": r_id}



@router.get("/routes")
def list_routes(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    routes = db.query(NetworkRoute).all()
    # Never return the encrypted credential blob to the client.
    return [
        {"id": r.id, "name": r.name, "pivot_host": r.pivot_host,
         "pivot_port": r.pivot_port, "pivot_username": r.pivot_username,
         "is_enabled": r.is_enabled}
        for r in routes
    ]


@router.post("/routes")
def add_route(body: NetworkRouteCreate, db: Session = Depends(get_db),
               user: User = Depends(require_admin)):
    route = NetworkRoute(
        name=body.name, pivot_host=body.pivot_host, pivot_port=body.pivot_port,
        pivot_username=body.pivot_username,
        credential_encrypted=encrypt_secret(body.credential),
        credential_kind=body.credential_kind,
    )
    db.add(route)
    db.commit()
    db.refresh(route)
    db.add(AuditLog(user_id=user.id, action="add_network_route",
                     outcome="success", detail=body.name))
    db.commit()
    return {"id": route.id, "name": route.name}


@router.delete("/networks/{network_id}")
def delete_network(network_id: int, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    net = db.get(AuthorizedNetwork, network_id)
    if not net:
        return {"status": "not_found"}
    cidr = net.cidr
    db.delete(net)
    db.commit()
    db.add(AuditLog(user_id=user.id, action="delete_authorized_network",
                     outcome="success", detail=cidr))
    db.commit()
    return {"status": "deleted", "id": network_id}


@router.delete("/routes/{route_id}")
def delete_route(route_id: int, db: Session = Depends(get_db),
                 user: User = Depends(require_admin)):
    route = db.get(NetworkRoute, route_id)
    if not route:
        return {"status": "not_found"}
    name = route.name
    db.delete(route)
    db.commit()
    db.add(AuditLog(user_id=user.id, action="delete_network_route",
                     outcome="success", detail=name))
    db.commit()
    return {"status": "deleted", "id": route_id}


@router.post("/routes/{route_id}/test")
def test_route(route_id: int, db: Session = Depends(get_db),
               user: User = Depends(require_admin)):
    route = db.get(NetworkRoute, route_id)
    if not route:
        return {"status": "not_found", "message": "Route not found"}
    import io
    import paramiko
    from ..security import decrypt_secret
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    secret = decrypt_secret(route.credential_encrypted)
    kwargs = {
        "hostname": route.pivot_host,
        "port": route.pivot_port,
        "username": route.pivot_username,
        "timeout": 5,
    }
    if route.credential_kind == "ssh_key":
        kwargs["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(secret))
    else:
        kwargs["password"] = secret
    try:
        client.connect(**kwargs)
        client.close()
        return {
            "status": "ok",
            "message": f"Successfully connected to SSH pivot {route.pivot_host}:{route.pivot_port}",
        }
    except Exception as exc:
        return {"status": "error", "message": f"SSH connection failed: {exc}"}


