import time
import jwt
import pytest
from api_gateway.gateway import APIGateway


@pytest.fixture
def client(secret, manager):
    app = APIGateway(secret, manager=manager).app
    app.config["TESTING"] = True
    return app.test_client()


def test_protected(client, manager):
    access, _ = manager.generate_tokens("user1")
    response = client.get("/protected", headers={"Authorization": f"Bearer {access}"})
    assert response.status_code == 200
    assert response.json == {"message": "Access granted", "user": "user1"}


@pytest.mark.parametrize("header", ["", "Bearer invalid", "Basic invalid", "Bearer", "Bearer a b"])
def test_bad_header(client, header):
    assert client.get("/protected", headers={"Authorization": header}).status_code == 401


def test_refresh_cannot_access_api(client, manager):
    _, refresh = manager.generate_tokens("user1")
    assert client.get("/protected", headers={"Authorization": f"Bearer {refresh}"}).status_code == 401


@pytest.mark.parametrize("kind", ["expired", "missing_sub", "signature"])
def test_invalid_access(client, secret, kind):
    payload = {"sub": "user1", "type": "access", "exp": time.time()+60}
    if kind == "expired": payload["exp"] = time.time()-60
    if kind == "missing_sub": del payload["sub"]
    token = jwt.encode(payload, secret[::-1] if kind == "signature" else secret, algorithm="HS256")
    assert client.get("/protected", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_refresh_and_revoke(client, manager):
    _, refresh = manager.generate_tokens("user1")
    response = client.post("/refresh", json={"refresh_token": refresh})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert client.post("/refresh", json={"refresh_token": refresh}).status_code == 401
    new_refresh = response.json["refresh_token"]
    assert client.post("/revoke", json={"refresh_token": new_refresh}).status_code == 204
    assert client.post("/refresh", json={"refresh_token": new_refresh}).status_code == 401


@pytest.mark.parametrize("data", [[], {}, {"refresh_token": []}, {"refresh_token": None}])
def test_malformed_json(client, data):
    assert client.post("/refresh", json=data).status_code == 401
