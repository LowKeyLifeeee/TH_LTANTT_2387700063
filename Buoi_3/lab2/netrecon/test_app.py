import os
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from netrecon.app import app
from netrecon.modules.runner import parse_ports, run_task, validate_target
from netrecon.modules.email_sender import get_smtp_credentials


class AppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.form = {"target": "127.0.0.1", "ports": "80", "mode": "vuln"}

    def test_default_recipient_and_assets(self):
        response = self.client.get("/")
        self.assertIn(b"thangminhnt20@gmail.com", response.data)
        with self.client.get("/static/app.js") as asset:
            self.assertEqual(asset.status_code, 200)

    def test_email_uses_default_recipient(self):
        with patch("netrecon.app.get_smtp_credentials", return_value=("sender@example.com", "test")), patch(
            "netrecon.app.send_email", return_value=True
        ) as sender:
            response = self.client.post("/scan", data=self.form)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(sender.call_args.args[0], "thangminhnt20@gmail.com")
        self.assertIn("Đã gửi".encode(), response.data)

    def test_missing_credentials_do_not_send(self):
        with patch("netrecon.app.get_smtp_credentials", return_value=("", "")), patch("netrecon.app.send_email") as sender:
            response = self.client.post("/scan", data=self.form)
        sender.assert_not_called()
        self.assertIn("Chưa gửi".encode(), response.data)

    def test_email_failure_is_visible(self):
        with patch("netrecon.app.get_smtp_credentials", return_value=("sender@example.com", "test")), patch(
            "netrecon.app.send_email", return_value=False
        ):
            response = self.client.post("/scan", data=self.form)
        self.assertIn("Gửi email thất bại".encode(), response.data)

    def test_blacklist_blocks_network_and_email(self):
        with patch("netrecon.modules.runner.async_scan_ports") as scanner, patch("netrecon.app.send_email") as sender:
            response = self.client.post("/scan", data={**self.form, "mode": "scan", "blacklist": "127.0.0.1"})
        self.assertEqual(response.status_code, 400)
        scanner.assert_not_called()
        sender.assert_not_called()

    def test_port_ranges_and_invalid_rate(self):
        self.assertEqual(parse_ports("80,22-23,80"), [22, 23, 80])
        with self.assertRaises(ValueError):
            parse_ports("1-65535")
        with self.assertRaises(ValueError):
            run_task("127.0.0.1", [80], "scan", float("nan"))

    def test_invalid_target_is_rejected_before_task(self):
        with patch("netrecon.app.run_task") as task:
            for target in ("", "http://127.0.0.1:5000", "999.1.1.1", "127.0.0.1 va 10.12.21.116"):
                with self.subTest(target=target):
                    response = self.client.post("/scan", data={**self.form, "target": target})
                    self.assertEqual(response.status_code, 400)
                    self.assertIn("Target IP".encode(), response.data)
            task.assert_not_called()

    def test_valid_individual_targets(self):
        for target in ("127.0.0.1", "10.12.21.116", "::1"):
            self.assertEqual(validate_target(target), target)

    def test_invalid_filters_name_the_correct_field(self):
        with patch("netrecon.modules.runner.async_scan_ports") as scanner:
            for field, text in (("whitelist", "vua tro choi"), ("blacklist", "choi game kem")):
                with self.subTest(field=field):
                    response = self.client.post("/scan", data={**self.form, "mode": "scan", field: text})
                    self.assertEqual(response.status_code, 400)
                    self.assertIn(field.capitalize().encode(), response.data)
                    self.assertNotIn("Target IP không hợp lệ".encode(), response.data)
            scanner.assert_not_called()

    def test_smtp_config_reloads_saved_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            with patch("netrecon.modules.email_sender.ENV_PATH", path), patch.dict(
                os.environ, {"SMTP_USER": "old@example.com", "SMTP_PASS": "old"}
            ):
                path.write_text("SMTP_USER=\nSMTP_PASS=\n", encoding="utf-8")
                self.assertEqual(get_smtp_credentials(), ("", ""))
                path.write_text("SMTP_USER=sender@example.com\nSMTP_PASS=test\n", encoding="utf-8-sig")
                self.assertEqual(get_smtp_credentials(), ("sender@example.com", "test"))


if __name__ == "__main__":
    unittest.main()
