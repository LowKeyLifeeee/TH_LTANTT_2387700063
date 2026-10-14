import secrets
import pytest
from token_manager.manager import TokenManager


@pytest.fixture
def secret():
    return secrets.token_urlsafe(48)


@pytest.fixture
def manager(secret):
    return TokenManager(secret)
