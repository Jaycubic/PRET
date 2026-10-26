import os
import sys
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# Ensure backend is on sys.path
backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.config import settings
settings.test_mode = True

from app.db import Base, get_db, User, Role, AuthorizedNetwork, Device
from app.security import hash_password, create_access_token
from app.main import app

# Test SQLite in-memory engine
TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


import asyncio
import httpx

class SyncClient:
    def __init__(self, asgi_app, base_url="http://testserver"):
        self.transport = httpx.ASGITransport(app=asgi_app)
        self.base_url = base_url

    def request(self, method, url, **kwargs):
        headers = kwargs.pop("headers", {})
        json_data = kwargs.pop("json", None)
        params = kwargs.pop("params", None)
        full_url = self.base_url + url if url.startswith("/") else url
        req = httpx.Request(method, full_url, headers=headers, json=json_data, params=params)
        resp = asyncio.run(self.transport.handle_async_request(req))
        asyncio.run(resp.aread())
        return resp

    def get(self, url, **kwargs): return self.request("GET", url, **kwargs)
    def post(self, url, **kwargs): return self.request("POST", url, **kwargs)
    def put(self, url, **kwargs): return self.request("PUT", url, **kwargs)
    def delete(self, url, **kwargs): return self.request("DELETE", url, **kwargs)


@pytest.fixture
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    test_client = SyncClient(app)
    yield test_client
    app.dependency_overrides.clear()




@pytest.fixture
def admin_user(db):
    user = User(
        username="testadmin",
        password_hash=hash_password("adminpass123"),
        role=Role.admin.value,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def admin_token(admin_user):
    return create_access_token(admin_user.username, admin_user.role)


@pytest.fixture
def operator_user(db):
    user = User(
        username="testoperator",
        password_hash=hash_password("operatorpass123"),
        role=Role.operator.value,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def operator_token(operator_user):
    return create_access_token(operator_user.username, operator_user.role)



@pytest.fixture
def authorized_network(db):
    net = AuthorizedNetwork(cidr="192.168.1.0/24", description="Test Lab Subnet")
    db.add(net)
    db.commit()
    db.refresh(net)
    return net
