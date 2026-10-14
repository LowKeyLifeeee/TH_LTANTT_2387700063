"""In-memory token lifecycle for a single-process lab."""
import secrets
import time
from threading import RLock
import jwt
from jwt_validator.validator import JWTValidator


class TokenManager:
    def __init__(self, secret, algorithm="HS256", access_exp=15, refresh_exp=60*24):
        if algorithm != "HS256":
            raise ValueError("TokenManager uses HS256")
        if len(secret.encode() if isinstance(secret, str) else secret) < 32:
            raise ValueError("Use a signing secret of at least 32 bytes")
        if access_exp <= 0 or refresh_exp <= 0:
            raise ValueError("Token lifetimes must be positive")
        self.secret, self.algorithm = secret, algorithm
        self.access_exp, self.refresh_exp = access_exp, refresh_exp
        self.validator = JWTValidator(secret)
        self._refresh = {}
        self._lock = RLock()

    def _generate(self, payload, exp_minutes):
        now = int(time.time())
        claims = {**payload, "iat": now, "exp": now + int(exp_minutes * 60),
                  "jti": secrets.token_urlsafe(24)}
        return jwt.encode(claims, self.secret, algorithm=self.algorithm)

    def generate_tokens(self, user_id):
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("user_id must be a nonempty string")
        with self._lock:
            now = time.time()
            self._refresh = {k: v for k, v in self._refresh.items() if v > now}
            access = self._generate({"sub": user_id, "type": "access"}, self.access_exp)
            refresh = self._generate({"sub": user_id, "type": "refresh"}, self.refresh_exp)
            claims = self.validator.validate(refresh, "refresh")["payload"]
            self._refresh[claims["jti"]] = claims["exp"]
            return access, refresh

    def _active_refresh(self, token):
        result = self.validator.validate(token, "refresh")
        if not result["valid"]:
            return None
        payload = result["payload"]
        return payload if payload.get("jti") in self._refresh else None

    def refresh_access_token(self, refresh_token):
        """Lab-compatible method; refresh token remains valid until revoked."""
        with self._lock:
            payload = self._active_refresh(refresh_token)
            if payload:
                return self._generate({"sub": payload["sub"], "type": "access"}, self.access_exp)
            return None

    def rotate_refresh_token(self, refresh_token):
        """Atomically consume a refresh token and return a new token pair."""
        with self._lock:
            payload = self._active_refresh(refresh_token)
            if payload is None:
                return None
            del self._refresh[payload["jti"]]
            return self.generate_tokens(payload["sub"])

    def revoke_refresh_token(self, refresh_token):
        with self._lock:
            payload = self._active_refresh(refresh_token)
            if payload is None:
                return False
            del self._refresh[payload["jti"]]
            return True
