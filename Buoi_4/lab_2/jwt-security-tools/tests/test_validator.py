import time
import jwt
import pytest
from jwt_validator.validator import JWTValidator


def test_valid_token(secret):
    token = jwt.encode({"sub": "test", "exp": time.time()+60}, secret, algorithm="HS256")
    result = JWTValidator(secret).validate(token)
    assert result["valid"] and result["payload"]["sub"] == "test"


@pytest.mark.parametrize("kind", ["expired", "signature", "none", "algorithm", "missing_exp", "future", "empty_sub", "malformed"])
def test_invalid_tokens(secret, kind):
    payload = {"sub": "test", "exp": time.time()+60}
    key, algorithm = secret, "HS256"
    if kind == "expired": payload["exp"] = time.time()-60
    if kind == "signature": key = secret[::-1]
    if kind == "none": key, algorithm = None, "none"
    if kind == "algorithm": algorithm = "HS512"
    if kind == "missing_exp": del payload["exp"]
    if kind == "future": payload["nbf"] = time.time()+3600
    if kind == "empty_sub": payload["sub"] = ""
    token = jwt.encode(payload, key, algorithm=algorithm) if kind != "malformed" else "invalid"
    assert not JWTValidator(secret).validate(token)["valid"]


def test_issuer_and_audience(secret):
    payload = {"sub": "test", "exp": time.time()+60, "iss": "issuer", "aud": "api"}
    token = jwt.encode(payload, secret, algorithm="HS256")
    assert JWTValidator(secret, issuer="issuer", audience="api").validate(token)["valid"]
    assert not JWTValidator(secret, issuer="other", audience="api").validate(token)["valid"]
    assert not JWTValidator(secret, issuer="issuer", audience="other").validate(token)["valid"]
