import time
import jwt
from jwt_cracker.cracker import JWTCracker


def test_crack_token(tmp_path, secret):
    words = tmp_path / "words.txt"
    words.write_text("wrong\n" + secret + "\n", encoding="utf-8")
    token = jwt.encode({"sub": "test", "exp": time.time()-60}, secret, algorithm="HS256")
    assert JWTCracker(token, words).crack() == secret


def test_no_match(tmp_path, secret):
    words = tmp_path / "words.txt"
    words.write_text("not-the-key\n", encoding="utf-8")
    token = jwt.encode({"sub": "test"}, secret, algorithm="HS256")
    assert JWTCracker(token, words).crack() is None


def test_none_rejected(tmp_path):
    words = tmp_path / "words.txt"
    words.write_text("candidate\n", encoding="utf-8")
    token = jwt.encode({"sub": "test"}, None, algorithm="none")
    assert JWTCracker(token, words).crack() is None
