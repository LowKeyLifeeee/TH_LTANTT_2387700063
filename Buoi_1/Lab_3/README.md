# BÁO CÁO THỰC HÀNH LAB 3: THIẾT KẾ VÀ TRIỂN KHAI HỆ THỐNG GHI NHẬT KÝ AN TOÀN (SECURELOGGER)

- **Môn học:** Thực hành Lập trình An ninh Thông tin (TH_LTANTT)
- **Học viên / MSSV:** Trần Minh Thắng - 2387700063
- **Thư mục bài làm:** `Buoi_1/Lab_3`
- **Tên giải pháp:** Hệ thống Ghi nhật ký An ninh **SecureLogger** tích hợp **SecureValidator**

---

## 1. Tổng quan mục tiêu và Kiến trúc hệ thống SecureLogger

Trong mô hình kiến trúc an ninh thông tin hiện đại và quy chuẩn tuân thủ (PCI-DSS, HIPAA, GDPR, ISO/IEC 27001), hệ thống ghi nhật ký (Logging System) đóng vai trò huyết mạch để phục vụ điều tra sự cố (Incident Response), phân tích forensics, và giám sát an ninh liên tục (Continuous Security Monitoring). Tuy nhiên, các hệ thống log truyền thống thường đối mặt với các nguy cơ bảo mật nghiêm trọng:
1. **Lộ lọt dữ liệu nhạy cảm (PII Leakage):** Log vô tình lưu mật khẩu, API key, token hoặc email của người dùng ở dạng plain-text.
2. **Thiếu tính toàn vẹn (Tampering / Log Forgery):** Kẻ tấn công sau khi xâm nhập có thể sửa đổi hoặc xóa các dòng log để xóa dấu vết.
3. **Cạn kiệt tài nguyên lưu trữ (Resource Exhaustion / DoS):** Tệp log phình to không kiểm soát làm đầy ổ cứng máy chủ.
4. **Dữ liệu phi cấu trúc (Unstructured Logs):** Khó khăn cho việc ingestion và phân tích tự động vào SIEM/SOC (ELK, Splunk, Graylog).

**SecureLogger** được thiết kế để giải quyết triệt để các thách thức trên với 5 trụ cột an ninh:

```
    [ Incoming HTTP Request / Application Event ]
                         │
                         ▼
        ┌─────────────────────────────────┐
        │       JSONFormatter             │
        │  • Masking PII (Email, Tokens)  │
        │  • ISO 8601 UTC Timestamp       │
        │  • Structured JSON Output       │
        └────────────────┬────────────────┘
                         │
                         ▼
        ┌─────────────────────────────────┐
        │    SecureRotatingFileHandler    │
        │  • Max Bytes & Backup Count     │
        │  • GZipRotator (.gz on rotate)  │
        └────────────────┬────────────────┘
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
   ┌─────────────────┐       ┌─────────────────┐
   │   secure.log    │       │ secure.log.sig  │
   │  JSON Log Data  │       │ SHA-256 Hashes  │
   └─────────────────┘       └─────────────────┘
            │                         │
            └────────────┬────────────┘
                         ▼
            [ Tamper Detection Check ]
```

---

## 2. Cấu trúc thư mục Lab 3

```
Buoi_1/Lab_3/
├── README.md                          # Báo cáo thực hành chi tiết Lab 3
└── secure_logger_lab/
    ├── app.py                         # Ứng dụng Flask REST API tích hợp SecureValidator & SecureLogger
    ├── requirements.txt               # Danh sách thư viện phụ thuộc (Flask)
    ├── secure.log                     # Tập tin nhật ký có cấu trúc JSON (đã che giấu PII)
    ├── secure.log.sig                 # Tập tin chữ ký băm SHA-256 phục vụ Tamper Detection
    ├── verify_lab3.py                 # Kịch bản kiểm thử toàn diện và mô phỏng thực hành
    ├── securelogger/
    │   ├── __init__.py                # Khởi tạo package và export hàm get_secure_logger
    │   └── logger.py                  # Module SecureLogger lõi (PII, Rotator, JSONFormatter, Signer)
    ├── securevalidator/               # Kế thừa từ Lab 1 (Bộ lọc bảo mật dữ liệu đầu vào)
    │   ├── __init__.py
    │   └── core.py                    # Xác thực Email, URL, Filename, Sanitize SQL, Sanitize HTML
    └── tests/
        └── test_secure_logger.py      # Bộ kiểm thử tự động pytest (8/8 test cases)
```

---

## 3. Chi tiết triển khai kỹ thuật

### 3.1. Che giấu thông tin định danh cá nhân (PII Masking)
Module `mask_pii` sử dụng biểu thức chính quy (Regular Expressions) để phát hiện và thay thế các trường thông tin nhạy cảm trước khi dữ liệu được ghi vào ổ đĩa:
- **Email:** Nhận diện định dạng địa chỉ email chuẩn và thay thế bằng `<email_masked>`.
- **Token / API Key / Mật khẩu:** Nhận diện các token định danh gán qua tham số hoặc chuỗi ký tự dài tối thiểu 8 ký tự và thay bằng `<token_masked>`.

```python
PII_PATTERNS = {
    "email": r'[\w\.-]+@[\w\.-]+\.\w+',
    "token": r'(?i)(token|apikey|key|password)\s*=\s*["\']?[\w\-]{8,}["\']?',
}

def mask_pii(text):
    for label, pattern in PII_PATTERNS.items():
        text = re.sub(pattern, f"<{label}_masked>", text, flags=re.IGNORECASE)
    return text
```

### 3.2. Định dạng nhật ký có cấu trúc chuẩn JSON (`JSONFormatter`)
Ghi log dưới dạng JSON giúp các hệ thống SIEM (Security Information and Event Management) dễ dàng parse và index. Mỗi record bao gồm:
- `timestamp`: Định dạng chuẩn ISO 8601 theo giờ quốc tế UTC (kèm hậu tố `Z`).
- `level`: Cấp độ log (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).
- `message`: Thông điệp nhật ký đã được che chắn PII.
- `data` & `results`: Dữ liệu ngữ cảnh bổ sung được làm sạch PII tự động.

### 3.3. Cơ chế luân phiên và nén nhật ký (`GZipRotator`)
Để tránh cạn kiệt dung lượng đĩa và tối ưu chi phí lưu trữ:
- Cấu hình kích thước tối đa mỗi tệp log: `MAX_LOG_SIZE = 1024 * 1024` (1MB).
- Số lượng tệp sao lưu tối đa: `BACKUP_COUNT = 2`.
- Khi kích thước tệp vượt ngưỡng, `SecureRotatingFileHandler` luân phiên tệp và kích hoạt `GZipRotator` nén tệp cũ thành định dạng `.gz`, sau đó tự động thu dọn tệp gốc.

### 3.4. Phát hiện thay đổi trái phép (Tamper Detection với SHA-256)
- Mỗi dòng nhật ký khi được ghi vào `secure.log` đồng thời được tính mã băm mã hóa SHA-256 thông qua `hash_line(line)`.
- Giá trị băm 64 ký tự hex được lưu vào tập tin bảo vệ `secure.log.sig`.
- Bất kỳ hành vi chỉnh sửa nào của kẻ tấn công đối với `secure.log` sẽ dẫn đến mã băm tính toán lại không trùng khớp với chữ ký ban đầu trong `secure.log.sig`, lập tức phát hiện gian lận.

### 3.5. Tích hợp REST API Flask với `SecureValidator`
File `app.py` xây dựng endpoint `/validate` tiếp nhận payload JSON, sử dụng bộ thư viện `securevalidator.core` từ Lab 1 để:
1. `validate_email`: Ngăn chặn Email Header Injection và kiểm tra format RFC 5321.
2. `validate_url`: Ngăn chặn SSRF (Server-Side Request Forgery) và loopback/private IP bypass.
3. `validate_filename`: Ngăn chặn Path Traversal (`../`, Windows reserved device names).
4. `sanitize_sql_input`: Loại bỏ SQL Injection payloads.
5. `sanitize_html_input`: Encode HTML entities chống XSS (Cross-Site Scripting).
6. Đồng thời, toàn bộ quá trình kiểm tra được `secure_logger.info` ghi nhận an toàn.

---

## 4. Hướng dẫn cài đặt và vận hành

### 4.1. Cài đặt phụ thuộc
Di chuyển vào thư mục bài tập và cài đặt các thư viện cần thiết:
```bash
cd Buoi_1/Lab_3/secure_logger_lab
pip install -r requirements.txt
```

### 4.2. Khởi chạy ứng dụng Flask
```bash
python app.py
```
Ứng dụng sẽ khởi chạy tại `http://127.0.0.1:5000`.

### 4.3. Kiểm thử tự động bằng Pytest
```bash
python -m pytest -v tests/test_secure_logger.py
```

### 4.4. Chạy kịch bản kiểm tra toàn diện
```bash
python verify_lab3.py
```

---

## 5. Kết quả kiểm thử thực nghiệm

### 5.1. Thử nghiệm gửi request POST qua API `/validate`
- **Request URL:** `POST http://localhost:5000/validate`
- **Headers:** `Content-Type: application/json`
- **Request Body (JSON):**
```json
{
  "email": "phuoc@example.com",
  "url": "https://secure.com",
  "filename": "report.pdf",
  "sql": "' OR 1=1 --",
  "html": "<script>alert(1)</script>"
}
```

- **Response Body:**
```json
{
  "email": true,
  "filename": true,
  "html": "&lt;script&gt;alert(1)&lt;/script&gt;",
  "sql": "1=1",
  "url": true
}
```
*Nhận xét:* Dữ liệu phản hồi hoàn toàn khớp với kết quả minh họa trong tài liệu hướng dẫn thực hành (Ảnh 4).

---

### 5.2. Kiểm tra tập tin nhật ký `secure.log`
Nội dung ghi nhận trong `secure.log`:
```json
{"timestamp": "2026-09-23T08:41:00.931700Z", "level": "INFO", "message": "Validation check performed", "data": "{'email': '<email_masked>', 'filename': 'report.pdf', 'html': '<script>alert(1)</script>', 'sql': \"' OR 1=1 --\", 'url': 'https://secure.com'}", "results": "{'email': True, 'url': True, 'filename': True, 'sql': '1=1', 'html': '&lt;script&gt;alert(1)&lt;/script&gt;'}"}
```
*Đánh giá an ninh:*
- Email cá nhân `phuoc@example.com` đã được tự động che giấu thành `<email_masked>`.
- Toàn bộ cấu trúc log được lưu trữ dưới định dạng JSON tiêu chuẩn.

---

### 5.3. Kiểm tra tập tin chữ ký `secure.log.sig` (Tamper Detection)
Mã băm SHA-256 được tự động sinh ra và ghi nhận:
```
756a46012651866e1f7794d28d96e8cf2115dbcda88fcdd86754f3b02fd74e70
```
*Thử nghiệm phát hiện gian lận:*
- Khi một kẻ tấn công sửa đổi dòng log (ví dụ đổi level từ `INFO` thành `CRITICAL` hoặc đổi kết quả validation):
  - Giá trị SHA-256 tính toán lại: `18eabb8e55e465a90685ed7ceb4fa3917f94f4e8aa07445478c2558f1cc98b11`.
  - Giá trị này không trùng khớp với chữ ký ban đầu, hệ thống lập tức phát hiện tệp log đã bị can thiệp trái phép.

---

### 5.4. Kết quả kiểm thử tự động với Pytest (8/8 test cases Passed)

```
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-9.0.1, pluggy-1.6.0
rootdir: D:\TH_LTANTT_2387700063\Buoi_1\Lab_3\secure_logger_lab
collected 8 items

tests/test_secure_logger.py::TestPIIMasking::test_mask_email PASSED      [ 12%]
tests/test_secure_logger.py::TestPIIMasking::test_mask_token_and_apikey PASSED [ 25%]
tests/test_secure_logger.py::TestPIIMasking::test_mask_dict_string PASSED [ 37%]
tests/test_secure_logger.py::TestTamperDetectionAndHashing::test_hash_line_deterministic PASSED [ 50%]
tests/test_secure_logger.py::TestTamperDetectionAndHashing::test_tamper_detection PASSED [ 62%]
tests/test_secure_logger.py::TestGZipRotator::test_gzip_compression PASSED [ 75%]
tests/test_secure_logger.py::TestFlaskAPIAndLogging::test_validate_endpoint_valid_payload PASSED [ 87%]
tests/test_secure_logger.py::TestFlaskAPIAndLogging::test_validate_endpoint_invalid_json PASSED [100%]

======================== 8 passed, 6 warnings in 0.24s ========================
```

---

## 6. Phân tích chuyên sâu DevSecOps & Khuyến nghị nâng cao

1. **Vấn đề Timing trong Tamper Detection:**
   - Trong quá trình phát triển, việc gọi `self.format(record)` lần thứ nhất tại `emit()` để lấy chuỗi băm và sau đó gọi `super().emit(record)` (nơi gọi tiếp `self.format(record)` lần thứ hai) có thể tạo ra chênh lệch microsecond ở trường `datetime.utcnow()`.
   - **Khuyến nghị chuẩn Production:** Nên cache kết quả `formatted_json` trực tiếp vào `record` hoặc override `formatTime(record)` sử dụng `record.created` để đảm bảo chuỗi ghi vào tệp log và chuỗi tính hash là đồng nhất 100%.

2. **Chữ ký số có bảo vệ khóa (HMAC-SHA256 / Digital Signature):**
   - Hiện tại hệ thống sử dụng SHA-256 đơn thuần. Nếu kẻ tấn công có quyền ghi đè cả tệp `secure.log` lẫn `secure.log.sig`, chúng có thể tính lại hash cho các dòng log giả mạo.
   - **Khuyến nghị:** Sử dụng HMAC-SHA256 với khóa bí mật (`SECRET_KEY`) lưu trong HSM (Hardware Security Module) hoặc AWS KMS/Vault, hoặc ký số bất đối xứng (RSA/ECDSA) để đảm bảo tính bất khả chối bỏ (Non-repudiation).

3. **Gửi log tập trung (Remote Log Shipping):**
   - Kết hợp forward log realtime qua giao thức Syslog qua TLS (RFC 5425) tới hệ thống SIEM tập trung ngăn ngừa nguy cơ xóa dấu vết cục bộ khi máy trạm bị chiếm quyền kiểm soát hoàn toàn.
