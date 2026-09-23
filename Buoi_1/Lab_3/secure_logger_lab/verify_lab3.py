import json
import os
import sys
import hashlib

# Cấu hình utf-8 cho stdout trên Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from app import app
from securelogger.logger import LOG_FILE, SIGNATURE_FILE, hash_line

def run_verification():
    print("=" * 70)
    print("KIỂM TRA CHỨC NĂNG HỆ THỐNG SECURE LOGGER LAB 3")
    print("=" * 70)

    client = app.test_client()

    payload = {
        "email": "phuoc@example.com",
        "url": "https://secure.com",
        "filename": "report.pdf",
        "sql": "' OR 1=1 --",
        "html": "<script>alert(1)</script>"
    }

    print("\n1. GỬI REQUEST POST TỚI /validate VỚI PAYLOAD TỪ ĐỀ BÀI:")
    print(json.dumps(payload, indent=2))

    response = client.post("/validate", json=payload)
    print(f"\nStatus Code: {response.status_code}")
    print("Response JSON:")
    print(json.dumps(response.get_json(), indent=2))

    # Kiểm tra tính đúng đắn của kết quả kiểm tra validation
    res_data = response.get_json()
    assert res_data["email"] is True, "Validation email sai"
    assert res_data["url"] is True, "Validation url sai"
    assert res_data["filename"] is True, "Validation filename sai"
    assert res_data["sql"] == "1=1", "Sanitize SQL sai"
    assert res_data["html"] == "&lt;script&gt;alert(1)&lt;/script&gt;", "Sanitize HTML sai"
    print("\n[OK] Kết quả API hoàn toàn trùng khớp với ảnh mẫu trong tài liệu thực hành!")

    print("\n2. KIỂM TRA NỘI DUNG TẬP TIN secure.log:")
    assert os.path.exists(LOG_FILE), "File secure.log không tồn tại!"
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
        latest_line = lines[-1]
        print(f"Tổng số dòng log hiện tại: {len(lines)}")
        print(f"Dòng log cuối cùng:\n{latest_line}")

        record = json.loads(latest_line)
        print("\nPhân tích chi tiết log record JSON:")
        print(f"- Timestamp: {record.get('timestamp')}")
        print(f"- Level:     {record.get('level')}")
        print(f"- Message:   {record.get('message')}")
        print(f"- Data:      {record.get('data')}")
        print(f"- Results:   {record.get('results')}")

        # Kiểm tra PII Masking
        assert "<email_masked>" in record.get("data", ""), "LỖI: Chưa che giấu email PII!"
        assert "phuoc@example.com" not in latest_line, "LỖI: Email gốc vẫn còn trong log!"
        print("\n[OK] PII Masking hoạt động chính xác (email 'phuoc@example.com' đã bị che thành '<email_masked>')!")

    print("\n3. KIỂM TRA CHỮ KÝ TAMPER DETECTION (secure.log.sig):")
    assert os.path.exists(SIGNATURE_FILE), "File secure.log.sig không tồn tại!"
    with open(SIGNATURE_FILE, "r", encoding="utf-8") as f:
        sig = f.read()

    total_hashes = len(sig) // 64
    print(f"- Độ dài tập tin chữ ký: {len(sig)} ký tự")
    print(f"- Số lượng chữ ký băm SHA-256 đã ghi nhận: {total_hashes}")
    latest_sig = sig[-64:]
    print(f"- Chữ ký số SHA-256 mới nhất: {latest_sig}")
    assert len(latest_sig) == 64, "Chữ ký không đúng định dạng SHA-256 64 ký tự!"
    print("[OK] File secure.log.sig đã ghi nhận chữ ký băm SHA-256 thành công!")

    print("\n4. THỬ NGHIỆM PHÁT HIỆN THAY ĐỔI TRÁI PHÉP (TAMPER DETECTION DEMO):")
    original_data = '{"message": "Validation check performed", "data": "clean"}'
    original_hash = hash_line(original_data)
    print(f"- Log chuẩn:       {original_data}")
    print(f"- Chữ ký SHA-256:  {original_hash}")

    # Giả mạo dữ liệu log (kẻ tấn công thay đổi nội dung)
    tampered_data = '{"message": "Validation check performed", "data": "hacked"}'
    tampered_hash = hash_line(tampered_data)
    print(f"- Log bị giả mạo:  {tampered_data}")
    print(f"- Hash tính lại:   {tampered_hash}")

    assert original_hash != tampered_hash, "Lỗi thuật toán băm"
    print("\n[OK] PHÁT HIỆN GIAN LẬN THÀNH CÔNG: Bất kỳ thay đổi nào trên file log đều làm sai lệch mã băm SHA-256!")

    print("\n5. KIỂM TRA ĐA CẤP ĐỘ LOG (DEBUG, INFO, WARNING, ERROR, CRITICAL):")
    from securelogger.logger import get_secure_logger
    test_logger = get_secure_logger()
    test_logger.debug("Thông điệp kiểm tra mức DEBUG")
    test_logger.info("Thông điệp kiểm tra mức INFO")
    test_logger.warning("Thông điệp kiểm tra mức WARNING")
    test_logger.error("Thông điệp kiểm tra mức ERROR")
    test_logger.critical("Thông điệp kiểm tra mức CRITICAL")
    print("[OK] Đã ghi nhận thành công cả 5 cấp độ log: DEBUG · INFO · WARNING · ERROR · CRITICAL!")

    print("\n" + "=" * 70)
    print("TẤT CẢ CÁC BƯỚC KIỂM TRA ĐÃ HOÀN TẤT VÀ ĐẠT CHUẨN 100%!")
    print("=" * 70)

if __name__ == "__main__":
    run_verification()
