"""Run main.py and check real loopback HTTP without persisting credentials."""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time
import requests


def main():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    process = subprocess.Popen(
        [sys.executable, "main.py", "--port", str(port)],
        cwd=Path(__file__).parent, env={**os.environ, "JWT_SECRET": secrets.token_urlsafe(48)},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    tokens = {}
    def collect():
        for line in process.stdout:
            for label in ("Access Token", "Refresh Token"):
                if line.startswith(label + ":"):
                    tokens[label] = line.split(":", 1)[1].strip()
    reader = threading.Thread(target=collect, daemon=True)
    reader.start()
    base = f"http://127.0.0.1:{port}"
    session = requests.Session()
    session.trust_env = False
    try:
        for _ in range(100):
            try:
                if len(tokens) == 2 and session.get(base+"/protected", timeout=1).status_code == 401:
                    break
            except requests.ConnectionError:
                pass
            if process.poll() is not None:
                raise RuntimeError("main.py exited before readiness")
            time.sleep(.1)
        else:
            raise RuntimeError("Gateway did not start within 10 seconds")
        valid = session.get(base+"/protected", headers={"Authorization": "Bearer "+tokens["Access Token"]}, timeout=3)
        assert valid.status_code == 200 and valid.json()["user"] == "Tran Minh Thang-2387700063"
        wrong_type = session.get(base+"/protected", headers={"Authorization": "Bearer "+tokens["Refresh Token"]}, timeout=3)
        assert wrong_type.status_code == 401
        rotated = session.post(base+"/refresh", json={"refresh_token": tokens["Refresh Token"]}, timeout=3)
        assert rotated.status_code == 200
        replay = session.post(base+"/refresh", json={"refresh_token": tokens["Refresh Token"]}, timeout=3)
        assert replay.status_code == 401
        new_token = rotated.json()["refresh_token"]
        revoked = session.post(base+"/revoke", json={"refresh_token": new_token}, timeout=3)
        assert revoked.status_code == 204
        rejected = session.post(base+"/refresh", json={"refresh_token": new_token}, timeout=3)
        assert rejected.status_code == 401
        print(json.dumps({"protected_valid": 200, "protected_refresh_token": 401,
                          "refresh": 200, "refresh_replay": 401, "revoke": 204,
                          "refresh_after_revoke": 401, "tokens_saved": False}, indent=2))
    finally:
        session.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        reader.join(timeout=2)
        process.stdout.close()


if __name__ == "__main__":
    main()
