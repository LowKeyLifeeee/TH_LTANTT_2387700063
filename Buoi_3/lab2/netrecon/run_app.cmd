@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0.venv\Scripts\python.exe" (
    echo Khong tim thay Python trong netrecon\.venv.
    echo Can tao moi truong ao va cai thu vien truoc khi chay.
    pause
    exit /b 1
)
echo Mo trinh duyet tai http://127.0.0.1:5000
echo Giu cua so nay mo khi su dung ung dung. Nhan Ctrl+C de dung.
"%~dp0.venv\Scripts\python.exe" "%~dp0app.py"
if errorlevel 1 (
    echo Ung dung dung do loi. Xem thong bao o phia tren.
    pause
)
