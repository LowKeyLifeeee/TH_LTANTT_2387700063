"""Authorization Code flow with state and PKCE S256."""
import base64
import hashlib
import secrets
import time
from urllib.parse import urlencode, urlsplit, parse_qsl, urlunsplit
import requests


class OAuthClient:
    def __init__(self, client_id, client_secret, auth_url, token_url, redirect_uri):
        for url in (auth_url, token_url):
            p = urlsplit(url)
            if p.scheme != "https" or not p.netloc or p.fragment or p.username:
                raise ValueError("OAuth endpoints must use HTTPS without credentials/fragments")
        p = urlsplit(redirect_uri)
        if not p.netloc or p.fragment or p.username or not (
            p.scheme == "https" or (p.scheme == "http" and p.hostname in {"localhost", "127.0.0.1", "::1"})
        ):
            raise ValueError("Redirect must use HTTPS or HTTP loopback")
        self.client_id, self.client_secret = client_id, client_secret
        self.auth_url, self.token_url, self.redirect_uri = auth_url, token_url, redirect_uri
        self._pending = {}

    def get_auth_url(self, scope="openid"):
        now = time.monotonic()
        self._pending = {k: v for k, v in self._pending.items() if v[1] > now}
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        self._pending[state] = (verifier, now + 600)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        parts = urlsplit(self.auth_url)
        params = dict(parse_qsl(parts.query))
        params.update(response_type="code", client_id=self.client_id, redirect_uri=self.redirect_uri,
                      scope=scope, state=state, code_challenge=challenge, code_challenge_method="S256")
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), ""))

    def get_token(self, code, state=None):
        if not isinstance(code, str) or not code or not isinstance(state, str):
            raise ValueError("A code and matching state are required")
        pending = self._pending.pop(state, None)
        if pending is None or pending[1] <= time.monotonic():
            raise ValueError("Invalid, expired or reused OAuth state")
        data = {"grant_type": "authorization_code", "code": code,
                "redirect_uri": self.redirect_uri, "client_id": self.client_id,
                "code_verifier": pending[0]}
        kwargs = {"auth": (self.client_id, self.client_secret)} if self.client_secret else {}
        response = requests.post(self.token_url, data=data, timeout=10, allow_redirects=False, **kwargs)
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError("Unexpected token endpoint response")
        result = response.json()
        if not isinstance(result, dict) or not isinstance(result.get("access_token"), str) or not result["access_token"]:
            raise ValueError("Token endpoint did not return an access token")
        return result
