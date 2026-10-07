# NetRecon

Có thể nhấp đúp `run_app.cmd` trong thư mục `netrecon` để khởi động bằng Python của môi trường ảo. Giữ cửa sổ terminal mở, sau đó truy cập http://127.0.0.1:5000. File này chạy được dù lệnh `python` chưa có trong PATH.

## Chạy trên PowerShell (tại thư mục lab2)

```powershell
.\netrecon\.venv\Scripts\python.exe -m pip install -r .\netrecon\requirements.txt -c .\netrecon\constraints.txt
.\netrecon\.venv\Scripts\python.exe .\netrecon\app.py
```

Mở http://127.0.0.1:5000. Email nhận kết quả mặc định: **thangminhnt20@gmail.com**.

Trong `netrecon/.env`, điền `SMTP_USER` (Gmail gửi) và `SMTP_PASS` (mật khẩu ứng dụng Gmail). Tên app trong bài là Netrecom; mật khẩu Netrecon được nêu trong đề không thay thế mật khẩu ứng dụng Gmail. File `.env` được bỏ qua bởi Git. Ứng dụng hiển thị trạng thái gửi email sau mỗi tác vụ web.

CLI (không gửi email):

```powershell
.\netrecon\.venv\Scripts\python.exe .\netrecon\cli.py --target 127.0.0.1 --ports 22,80,443 --mode scan --rate-limit 10
```

Thêm `--whitelist IP` hoặc `--blacklist IP`, có thể lặp lại. Blacklist ưu tiên hơn whitelist. Log có thời gian tại `netrecon/netrecon.log`.

Service Detection cần cài Nmap và có `nmap` trong PATH. Phần theo ảnh hiện dùng TCP connect; UDP và kỹ thuật quét ẩn mình chưa được triển khai. Network Map đọc bảng ARP cục bộ. VulnChecker chỉ tra danh sách CVE minh họa theo cổng, chưa xác nhận lỗ hổng. Chỉ thực hiện với mục tiêu được phép trong mạng thực hành.

Gói `htmx` trên PyPI được giữ đúng danh sách trong ảnh; giao diện cập nhật kết quả bằng JavaScript cục bộ. `constraints.txt` giới hạn phụ thuộc để tương thích Pydantic 1 của gói này.
