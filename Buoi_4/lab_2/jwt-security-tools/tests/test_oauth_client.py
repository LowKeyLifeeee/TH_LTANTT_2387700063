import base64
import hashlib
from urllib.parse import urlsplit, parse_qs
from unittest.mock import Mock
import pytest
import requests
from oauth_client.client import OAuthClient


@pytest.fixture
def oauth(secret):
    return OAuthClient("client_id", secret, "https://auth.example/authorize?tenant=lab",
                       "https://auth.example/token", "http://127.0.0.1/callback")


def test_auth_code_pkce(oauth, monkeypatch):
    query = parse_qs(urlsplit(oauth.get_auth_url()).query)
    assert query["client_id"] == ["client_id"] and query["tenant"] == ["lab"]
    assert query["code_challenge_method"] == ["S256"]
    response = Mock(status_code=200)
    response.json.return_value = {"access_token": "test-response-token"}
    post = Mock(return_value=response)
    monkeypatch.setattr(requests, "post", post)
    assert oauth.get_token("test-code", query["state"][0]) == response.json.return_value
    kwargs = post.call_args.kwargs
    digest = hashlib.sha256(kwargs["data"]["code_verifier"].encode()).digest()
    assert base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == query["code_challenge"][0]
    assert kwargs["timeout"] == 10 and kwargs["allow_redirects"] is False
    assert "client_secret" not in kwargs["data"]
    with pytest.raises(ValueError): oauth.get_token("test-code", query["state"][0])


def test_wrong_state(oauth, monkeypatch):
    post = Mock()
    monkeypatch.setattr(requests, "post", post)
    oauth.get_auth_url()
    with pytest.raises(ValueError): oauth.get_token("test-code", "wrong")
    post.assert_not_called()


def test_expired_state(oauth):
    state = parse_qs(urlsplit(oauth.get_auth_url()).query)["state"][0]
    verifier, _ = oauth._pending[state]
    oauth._pending[state] = (verifier, 0)
    with pytest.raises(ValueError): oauth.get_token("test-code", state)


def test_http_failure(oauth, monkeypatch):
    state = parse_qs(urlsplit(oauth.get_auth_url()).query)["state"][0]
    response = Mock()
    response.raise_for_status.side_effect = requests.HTTPError("failed")
    monkeypatch.setattr(requests, "post", Mock(return_value=response))
    with pytest.raises(requests.HTTPError): oauth.get_token("test-code", state)


def test_insecure_endpoint():
    with pytest.raises(ValueError):
        OAuthClient("id", None, "http://auth.example", "https://auth.example/token", "http://localhost")
