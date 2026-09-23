import os
import sys
import json
import gzip
import hashlib
import pytest

# Thêm đường dẫn thư mục secure_logger_lab vào sys.path để import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from securelogger.logger import (
    mask_pii, hash_line, append_signature,
    JSONFormatter, GZipRotator, get_secure_logger,
    LOG_FILE, SIGNATURE_FILE
)
from app import app


class TestPIIMasking:
    """Kiểm tra chức năng che giấu thông tin định danh cá nhân (PII)"""

    def test_mask_email(self):
        sample = "Liên hệ user@domain.com hoặc admin.test@company.vn để nhận hỗ trợ."
        masked = mask_pii(sample)
        assert "user@domain.com" not in masked
        assert "admin.test@company.vn" not in masked
        assert "<email_masked>" in masked

    def test_mask_token_and_apikey(self):
        sample1 = "User credentials: token=abcdef1234"
        sample2 = 'Secret access: apikey="my_api_key"'
        sample3 = "Database auth: " + "pass" + "word='Secret123'"

        assert "<token_masked>" in mask_pii(sample1)
        assert "<token_masked>" in mask_pii(sample2)
        assert "<token_masked>" in mask_pii(sample3)

    def test_mask_dict_string(self):
        data = {"email": "phuoc@example.com", "info": "token=secret_token_123456"}
        masked = mask_pii(str(data))
        assert "phuoc@example.com" not in masked
        assert "<email_masked>" in masked
        assert "<token_masked>" in masked


class TestTamperDetectionAndHashing:
    """Kiểm tra cơ chế phát hiện thay đổi trái phép (Tamper Detection) bằng SHA-256"""

    def test_hash_line_deterministic(self):
        line = '{"message": "Validation check performed"}'
        expected_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
        assert hash_line(line) == expected_hash

    def test_tamper_detection(self):
        original_log = '{"level": "INFO", "message": "User login success"}'
        tampered_log = '{"level": "INFO", "message": "User login failed"}'

        sig = hash_line(original_log)

        # Log gốc khớp chữ ký
        assert hash_line(original_log) == sig
        # Log bị sửa đổi sẽ không khớp chữ ký
        assert hash_line(tampered_log) != sig


class TestGZipRotator:
    """Kiểm tra cơ chế luân phiên và nén log bằng gzip"""

    def test_gzip_compression(self, tmp_path):
        source = tmp_path / "test.log"
        dest = tmp_path / "test.log.1"

        log_content = b"Line 1: Log entry\nLine 2: Another log entry\n"
        source.write_bytes(log_content)

        rotator = GZipRotator()
        rotator(str(source), str(dest))

        # File nguồn phải bị xóa sau khi nén
        assert not source.exists()

        # File nén phải tồn tại với đuôi .gz
        gz_file = tmp_path / "test.log.1.gz"
        assert gz_file.exists()

        # Giải nén và kiểm tra nội dung
        with gzip.open(gz_file, "rb") as f:
            decompressed = f.read()
        assert decompressed == log_content


class TestFlaskAPIAndLogging:
    """Kiểm tra endpoint /validate và tích hợp ghi log an toàn"""

    @pytest.fixture
    def client(self):
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client

    def test_validate_endpoint_valid_payload(self, client):


        payload = {
            "email": "phuoc@example.com",
            "url": "https://secure.com",
            "filename": "report.pdf",
            "sql": "' OR 1=1 --",
            "html": "<script>alert(1)</script>"
        }

        response = client.post("/validate", json=payload)
        assert response.status_code == 200

        data = response.get_json()
        assert data["email"] is True
        assert data["url"] is True
        assert data["filename"] is True
        assert data["sql"] == "1=1"
        assert data["html"] == "&lt;script&gt;alert(1)&lt;/script&gt;"

        # Kiểm tra file secure.log đã được tạo và chứa dữ liệu masked
        assert os.path.exists(LOG_FILE)
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            log_contents = f.read()

        assert "phuoc@example.com" not in log_contents
        assert "<email_masked>" in log_contents
        assert "Validation check performed" in log_contents

        # Kiểm tra file signature
        assert os.path.exists(SIGNATURE_FILE)
        with open(SIGNATURE_FILE, "r", encoding="utf-8") as f:
            sig_contents = f.read()
        assert len(sig_contents) >= 64

    def test_validate_endpoint_invalid_json(self, client):
        response = client.post(
            "/validate",
            data="INVALID_JSON_RAW_DATA",
            content_type="application/json"
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "Invalid JSON format"
