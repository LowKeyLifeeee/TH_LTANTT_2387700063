import os

# Thông tin nhạy cảm đã được loại bỏ và lấy an toàn từ biến môi trường
password = os.environ.get("DB_PASSWORD", "")
