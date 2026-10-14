from flask import Flask, jsonify, request
from jwt_validator.validator import JWTValidator


class APIGateway:
    def __init__(self, secret, algorithm="HS256", manager=None):
        self.app = Flask(__name__)
        self.app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
        self.validator = JWTValidator(secret, [algorithm])
        self.manager = manager
        self.setup_routes()

    def setup_routes(self):
        @self.app.get("/")
        def index():
            return jsonify(
                message="JWTSECURE API is running",
                instructions="Send your Access Token in the Authorization: Bearer <token> header to GET /protected.",
                endpoints={"/protected": "GET", "/refresh": "POST", "/revoke": "POST"},
            )

        def denied():
            return jsonify(message="Access denied"), 401, {"WWW-Authenticate": "Bearer"}

        @self.app.get("/protected")
        def protected():
            parts = request.headers.get("Authorization", "").split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return denied()
            result = self.validator.validate(parts[1], "access")
            if not result["valid"]:
                return denied()
            return jsonify(message="Access granted", user=result["payload"]["sub"])

        @self.app.post("/refresh")
        def refresh():
            data = request.get_json(silent=True)
            if self.manager is None or not isinstance(data, dict):
                return denied()
            pair = self.manager.rotate_refresh_token(data.get("refresh_token"))
            if pair is None:
                return denied()
            return jsonify(access_token=pair[0], refresh_token=pair[1]), 200, {"Cache-Control": "no-store"}

        @self.app.post("/revoke")
        def revoke():
            data = request.get_json(silent=True)
            if self.manager is None or not isinstance(data, dict):
                return denied()
            self.manager.revoke_refresh_token(data.get("refresh_token"))
            return "", 204

    def run(self, port=5000):
        self.app.run(host="127.0.0.1", port=port, debug=False)
