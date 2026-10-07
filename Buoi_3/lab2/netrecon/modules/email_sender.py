import smtplib
import os
from email.message import EmailMessage
from pathlib import Path
from dotenv import dotenv_values
from .log_utils import log

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def get_smtp_credentials():
    """Doc lai file moi lan gui de nhan cau hinh vua duoc luu."""
    config = dotenv_values(ENV_PATH, encoding="utf-8-sig", interpolate=False)
    user = (config.get("SMTP_USER", os.getenv("SMTP_USER", "")) or "").strip()
    password = (config.get("SMTP_PASS", os.getenv("SMTP_PASS", "")) or "").strip()
    return user, password


def send_email(receiver_email, subject, body, smtp_user, smtp_pass):
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = smtp_user
    message["To"] = receiver_email
    message.set_content(body)
    log(f"Email request to {receiver_email}")
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as smtp:
            smtp.login(smtp_user, smtp_pass)
            smtp.send_message(message)
        log(f"Email sent to {receiver_email}")
        print(f"[+] Email sent to {receiver_email}")
        return True
    except (OSError, smtplib.SMTPException) as error:
        log(f"Email failed: {type(error).__name__}")
        print(f"[-] Email failed: {type(error).__name__}")
        return False
