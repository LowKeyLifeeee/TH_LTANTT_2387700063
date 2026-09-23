import unittest
from securevalidator import (
    validate_email, validate_url, validate_filename,
    sanitize_sql_input, sanitize_html_input
)

class TestValidators(unittest.TestCase):
    def setUp(self):
        print("\n Running:", self._testMethodName)

    # -------------------------------------------------------------
    # 1. Email Validator Tests
    # -------------------------------------------------------------
    def test_validate_email_valid(self):
        self.assertTrue(validate_email("user@example.com"))
        self.assertTrue(validate_email("john.doe+filter@sub.domain.org"))

    def test_validate_email_invalid(self):
        self.assertFalse(validate_email("user@@example..com"))
        self.assertFalse(validate_email("plainaddress"))
        self.assertFalse(validate_email("@missingusername.com"))

    def test_validate_email_bypass_crlf_injection(self):
        # Header injection attack (CRLF)
        self.assertFalse(validate_email("user@example.com\r\nBcc: victim@example.com"))

    def test_validate_email_bypass_consecutive_dots(self):
        self.assertFalse(validate_email("user..name@example.com"))
        self.assertFalse(validate_email(".user@example.com"))

    # -------------------------------------------------------------
    # 2. URL Validator & SSRF Prevention Tests
    # -------------------------------------------------------------
    def test_validate_url_valid(self):
        self.assertTrue(validate_url("https://example.com"))

    def test_validate_url_invalid(self):
        self.assertFalse(validate_url("ftp://example.com"))

    def test_validate_url_ssrf_localhost(self):
        self.assertFalse(validate_url("http://localhost"))
        self.assertFalse(validate_url("http://localhost:8080/admin"))
        self.assertFalse(validate_url("http://127.0.0.1:5000"))

    def test_validate_url_ssrf_private_and_metadata_ip(self):
        # AWS / GCP / Azure metadata endpoint
        self.assertFalse(validate_url("http://169.254.169.254/latest/meta-data/"))
        # Private LAN addresses
        self.assertFalse(validate_url("http://192.168.1.1/router"))
        self.assertFalse(validate_url("http://10.0.0.1"))
        self.assertFalse(validate_url("http://172.16.0.1"))

    # -------------------------------------------------------------
    # 3. Filename Validator & Path Traversal Prevention Tests
    # -------------------------------------------------------------
    def test_validate_filename_valid(self):
        self.assertTrue(validate_filename("report.pdf"))
        self.assertTrue(validate_filename("my_document-2026.docx"))

    def test_validate_filename_traversal(self):
        self.assertFalse(validate_filename("../../etc/passwd"))
        self.assertFalse(validate_filename("..\\..\\windows\\system32\\config\\sam"))

    def test_validate_filename_null_byte_and_special_chars(self):
        # Null byte injection
        self.assertFalse(validate_filename("image.png\x00.exe"))
        # Dangerous Windows characters
        self.assertFalse(validate_filename("secret:stream.txt"))
        self.assertFalse(validate_filename("file*.txt"))
        self.assertFalse(validate_filename("file?.txt"))

    def test_validate_filename_windows_reserved_device_names(self):
        self.assertFalse(validate_filename("CON.txt"))
        self.assertFalse(validate_filename("aux.png"))
        self.assertFalse(validate_filename("NUL"))
        self.assertFalse(validate_filename("com1.dat"))

    # -------------------------------------------------------------
    # 4. SQL Sanitizer Tests
    # -------------------------------------------------------------
    def test_sanitize_sql_input_injection(self):
        input_str = "' OR 1=1 --"
        sanitized = sanitize_sql_input(input_str)
        self.assertNotIn("'", sanitized)
        self.assertNotIn("--", sanitized)
        self.assertNotIn("OR", sanitized.upper())

    def test_sanitize_sql_input_safe_text(self):
        input_str = "hello world"
        sanitized = sanitize_sql_input(input_str)
        self.assertEqual(sanitized, "hello world")

    def test_sanitize_sql_input_union_select(self):
        input_str = "1' UNION SELECT username, password FROM users --"
        sanitized = sanitize_sql_input(input_str)
        self.assertNotIn("UNION", sanitized.upper())
        self.assertNotIn("SELECT", sanitized.upper())

    def test_sanitize_sql_input_block_comments(self):
        input_str = "admin'/*comment*/OR 1=1"
        sanitized = sanitize_sql_input(input_str)
        self.assertNotIn("/*", sanitized)
        self.assertNotIn("*/", sanitized)
        self.assertNotIn("OR", sanitized.upper())

    # -------------------------------------------------------------
    # 5. HTML Sanitizer & XSS Prevention Tests
    # -------------------------------------------------------------
    def test_sanitize_html_input_script(self):
        input_str = '<script>alert("XSS")</script>'
        sanitized = sanitize_html_input(input_str)
        self.assertEqual(sanitized, '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;')

    def test_sanitize_html_input_safe_text(self):
        input_str = "Hello World"
        sanitized = sanitize_html_input(input_str)
        self.assertEqual(sanitized, "Hello World")

    def test_sanitize_html_input_javascript_pseudo_protocol(self):
        input_str = 'javascript:alert(1)'
        sanitized = sanitize_html_input(input_str)
        self.assertNotIn('javascript:', sanitized.lower())
        self.assertTrue(sanitized.startswith('blocked:'))

if __name__ == "__main__":
    unittest.main()
