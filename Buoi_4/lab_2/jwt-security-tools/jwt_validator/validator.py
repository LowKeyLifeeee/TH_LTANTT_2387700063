"""Validate signed JWTs using a server-configured algorithm."""
import jwt


class JWTValidator:
    def __init__(self, secret, algorithms=None, issuer=None, audience=None):
        self.secret = secret
        self.algorithms = list(algorithms or ["HS256"])
        if not self.algorithms or any(a not in {"HS256", "HS384", "HS512"} for a in self.algorithms):
            raise ValueError("This lab supports HMAC algorithms only")
        self.issuer = issuer
        self.audience = audience

    def validate(self, token: str, expected_type=None):
        try:
            required = ["exp", "sub"]
            if self.issuer is not None:
                required.append("iss")
            if self.audience is not None:
                required.append("aud")
            payload = jwt.decode(
                token, self.secret, algorithms=self.algorithms,
                issuer=self.issuer, audience=self.audience,
                options={"require": required},
            )
            if not isinstance(payload["sub"], str) or not payload["sub"]:
                raise jwt.InvalidTokenError("Invalid subject")
            if expected_type and payload.get("type") != expected_type:
                raise jwt.InvalidTokenError("Wrong token type")
            return {"valid": True, "payload": payload}
        except jwt.ExpiredSignatureError:
            return {"valid": False, "reason": "Token expired"}
        except jwt.InvalidSignatureError:
            return {"valid": False, "reason": "Invalid signature"}
        except (jwt.InvalidTokenError, TypeError, ValueError) as exc:
            return {"valid": False, "reason": str(exc)}
