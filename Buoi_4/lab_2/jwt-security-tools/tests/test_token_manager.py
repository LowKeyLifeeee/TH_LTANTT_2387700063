from concurrent.futures import ThreadPoolExecutor
import time
import jwt
import pytest
from token_manager.manager import TokenManager


def test_creation_and_refresh(manager, secret):
    access, refresh = manager.generate_tokens("user1")
    payload = jwt.decode(access, secret, algorithms=["HS256"])
    assert payload["sub"] == "user1" and payload["type"] == "access"
    assert manager.refresh_access_token(refresh) is not None
    assert manager.refresh_access_token(access) is None


def test_revoke(manager):
    _, refresh = manager.generate_tokens("user1")
    assert manager.revoke_refresh_token(refresh)
    assert manager.refresh_access_token(refresh) is None
    assert not manager.revoke_refresh_token(refresh)


def test_rotation_and_replay(manager):
    _, refresh = manager.generate_tokens("user1")
    pair = manager.rotate_refresh_token(refresh)
    assert pair and pair[1] != refresh
    assert manager.rotate_refresh_token(refresh) is None
    assert manager.refresh_access_token(pair[1]) is not None


def test_concurrent_rotation(manager):
    _, refresh = manager.generate_tokens("user1")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(manager.rotate_refresh_token, [refresh, refresh]))
    assert sum(r is not None for r in results) == 1


@pytest.mark.parametrize("token", [None, "invalid", "", {}, []])
def test_bad_refresh(manager, token):
    assert manager.refresh_access_token(token) is None
    assert manager.rotate_refresh_token(token) is None
    assert not manager.revoke_refresh_token(token)


def test_expired_refresh(manager, secret):
    _, refresh = manager.generate_tokens("user1")
    claims = jwt.decode(refresh, secret, algorithms=["HS256"])
    claims["exp"] = time.time()-60
    expired = jwt.encode(claims, secret, algorithm="HS256")
    assert manager.refresh_access_token(expired) is None


def test_unregistered_refresh(manager, secret):
    other = TokenManager(secret)
    _, refresh = other.generate_tokens("user1")
    assert manager.refresh_access_token(refresh) is None


def test_weak_signing_key():
    with pytest.raises(ValueError):
        TokenManager("short")
