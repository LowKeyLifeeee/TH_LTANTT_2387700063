from flask import Flask, render_template, request

if __package__:
    from .modules.runner import DEFAULT_EMAIL, run_task, parse_ports, validate_target
    from .modules.email_sender import send_email, get_smtp_credentials
    from .modules.log_utils import log
else:
    from modules.runner import DEFAULT_EMAIL, run_task, parse_ports, validate_target
    from modules.email_sender import send_email, get_smtp_credentials
    from modules.log_utils import log

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


@app.get("/")
def index():
    return render_template("index.html", default_email=DEFAULT_EMAIL)


@app.post("/scan")
def scan():
    try:
        target = validate_target(request.form.get("target", ""))
        ports = parse_ports(request.form.get("ports", "22,80,443"))
        rate_limit = float(request.form.get("rate_limit", "10"))
        mode = request.form.get("mode", "all")
        email = request.form.get("email", DEFAULT_EMAIL).strip()
        if "@" not in email or any(char in email for char in "\r\n"):
            raise ValueError("Email nhan ket qua khong hop le.")
        whitelist = request.form.get("whitelist", "").split()
        blacklist = request.form.get("blacklist", "").split()
        result = run_task(target, ports, mode, rate_limit, whitelist, blacklist)
    except ValueError as error:
        log(f"Invalid web request: {error}")
        return render_template("result.html", result={}, error=str(error)), 400

    smtp_user, smtp_pass = get_smtp_credentials()
    if smtp_user and smtp_pass:
        body = f"Kết quả NetRecon:\nTarget IP: {target}\n\n" + "\n\n".join(
            f"--- {key.upper()} ---\n{value}" for key, value in result.items()
        )
        sent = send_email(email, "Kết quả quét từ NetRecon", body, smtp_user, smtp_pass)
        email_status = f"Đã gửi kết quả tới {email}." if sent else "Gửi email thất bại. Kiểm tra cấu hình SMTP."
    else:
        email_status = f"Chưa gửi email tới {email}: cần điền SMTP_USER và SMTP_PASS trong .env."
        log("Email skipped: SMTP credentials missing")
    return render_template("result.html", result=result, email_status=email_status)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
