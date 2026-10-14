"""Offline dictionary exercise for tokens owned by the lab user."""
import jwt


class JWTCracker:
    def __init__(self, token, wordlist_path):
        self.token = token
        self.wordlist_path = wordlist_path

    def try_secret(self, secret):
        try:
            # Only test the signature: expiration/claims do not change the key.
            jwt.api_jws.decode_complete(self.token, secret, algorithms=["HS256"])
            return secret
        except (jwt.InvalidTokenError, ValueError, TypeError):
            return None

    def crack(self):
        with open(self.wordlist_path, encoding="utf-8") as words:
            for line in words:
                candidate = line.rstrip("\r\n")
                if candidate and self.try_secret(candidate) is not None:
                    return candidate
        return None
