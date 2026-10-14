import argparse
import os
import secrets
from api_gateway.gateway import APIGateway
from token_manager.manager import TokenManager


def main():
    parser = argparse.ArgumentParser(description="JWTSECURE local lab")
    parser.add_argument("--user", default="Tran Minh Thang-2387700063")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    secret = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(48)
    manager = TokenManager(secret)
    access, refresh = manager.generate_tokens(args.user)
    print("Access Token:", access, flush=True)
    print("Refresh Token:", refresh, flush=True)
    APIGateway(secret, manager=manager).run(args.port)


if __name__ == "__main__":
    main()
