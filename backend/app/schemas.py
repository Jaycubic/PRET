from datetime import datetime
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class ProbeRequest(BaseModel):
    ip_or_hostname: str
    timeout: float = 2.0


class DeviceCreate(BaseModel):
    ip_or_hostname: str
    port: int = 9100
    protocol_hint: str = "auto"
    device_type: str = "printer"
    model: str = ""


class DeviceOut(BaseModel):
    id: int
    ip_or_hostname: str
    resolved_ip: str
    port: int
    hostname: str
    model: str = ""
    status: str
    source: str = "manual"
    device_type: str = "printer"
    model_config = {"from_attributes": True}


class JobCreate(BaseModel):
    device_id: int
    adapter_id: str
    operation_id: str
    params: dict = {}
    confirm: bool = False


class JobOut(BaseModel):
    id: int
    device_id: int | None
    adapter_id: str
    operation_id: str
    status: str
    is_state_changing: bool = False
    confirmed: bool = False
    requested_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    model_config = {"from_attributes": True}


class JobEvent(BaseModel):
    stage: str
    status: str
    message: str
    timestamp: str


class AuthorizedNetworkCreate(BaseModel):
    cidr: str
    description: str = ""
    route_id: int | None = None


class NetworkRouteCreate(BaseModel):
    name: str
    pivot_host: str
    pivot_port: int = 22
    pivot_username: str
    credential: str  # private key PEM text, or password
    credential_kind: str = "ssh_key"
