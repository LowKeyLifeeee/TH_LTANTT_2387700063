import re
import html
import urllib.parse
import os
import socket
import ipaddress

def validate_email(email: str) -> bool:
    """
    Validate email format and prevent Header Injection (CRLF) and structural bypasses.
    - Limits total length to 254 characters (RFC 5321).
    - Prevents CRLF injection (\r, \n) to stop Email Header Injection attacks.
    - Disallows consecutive dots and invalid boundary dots.
    - Supports valid RFC-compliant characters like '+' for sub-addressing.
    """
    if not isinstance(email, str) or len(email) > 254:
        return False

    # Prevent Email Header Injection via CRLF
    if "\r" in email or "\n" in email:
        return False

    # Disallow consecutive dots
    if ".." in email:
        return False

    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$'
    if not re.fullmatch(pattern, email):
        return False

    local_part, _, domain_part = email.rpartition('@')
    # Check boundaries of local and domain parts
    if local_part.startswith('.') or local_part.endswith('.'):
        return False
    if domain_part.startswith('.') or domain_part.endswith('.'):
        return False

    return True


def validate_url(url: str) -> bool:
    """
    Validate URL and prevent Server-Side Request Forgery (SSRF).
    - Ensures scheme is strictly http or https.
    - Blocks localhost, loopback, private IP ranges (10.x, 172.16-31.x, 192.168.x),
      link-local addresses (e.g., 169.254.169.254 cloud metadata), and IPv6 loopbacks ([::1]).
    - Resolves domain names to IP addresses to detect internal host redirection.
    """
    if not isinstance(url, str):
        return False

    try:
        parsed = urllib.parse.urlparse(url.strip())
        if parsed.scheme.lower() not in ['http', 'https']:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Block explicit localhost domains
        if hostname.lower() in ['localhost', 'localhost.localdomain']:
            return False

        def is_forbidden_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
            return (
                ip_obj.is_loopback or
                ip_obj.is_private or
                ip_obj.is_link_local or
                ip_obj.is_reserved or
                ip_obj.is_multicast or
                ip_obj.is_unspecified
            )

        # Check if hostname is an IP literal
        try:
            ip = ipaddress.ip_address(hostname)
            if is_forbidden_ip(ip):
                return False
            return True
        except ValueError:
            pass

        # Resolve hostname via DNS to verify target IP
        addr_info = socket.getaddrinfo(hostname, None)
        if not addr_info:
            return False

        for _, _, _, _, sockaddr in addr_info:
            resolved_ip = ipaddress.ip_address(sockaddr[0])
            if is_forbidden_ip(resolved_ip):
                return False

        return True
    except Exception:
        return False


def validate_filename(filename: str) -> bool:
    """
    Prevent Path Traversal and illegal filesystem manipulations.
    - Limits length to 255 characters.
    - Blocks null byte injections (\x00).
    - Blocks directory traversal sequences (..) and directory separators (/ and \\).
    - Blocks dangerous cross-platform characters (: * ? \" < > |).
    - Blocks Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9).
    - Blocks trailing dots and spaces that cause truncation on Windows.
    """
    if not isinstance(filename, str) or not filename:
        return False

    if len(filename) > 255:
        return False

    # Block null byte
    if "\x00" in filename:
        return False

    # Block path traversal tokens and path separators
    if ".." in filename or "/" in filename or "\\" in filename:
        return False

    # Block forbidden characters in Windows and cross-platform filesystems
    if re.search(r'[\x00-\x1f:*?"<>|]', filename):
        return False

    # Block trailing dots or spaces which can cause filesystem truncation
    if filename.endswith('.') or filename.endswith(' '):
        return False

    # Block Windows reserved device names
    base_name = filename.split('.')[0].upper()
    reserved_names = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10))
    }
    if base_name in reserved_names:
        return False

    return os.path.basename(filename) == filename


def sanitize_sql_input(input_str: str) -> str:
    """
    Sanitize input string to mitigate SQL Injection risks.
    - Recursively removes dangerous SQL tokens, comments, and keywords.
    - Handles block comments (/* ... */) and line comments (-- and #).
    - NOTE: Blacklist sanitization is inherently risky. For complete security,
      ALWAYS use Parameterized Queries (Prepared Statements) in database operations.
    """
    if not isinstance(input_str, str):
        return ""

    sanitized = input_str.replace("\x00", "")

    # Replace block comments with space to preserve word boundaries
    sanitized = re.sub(r"/\*.*?\*/", " ", sanitized)

    keywords_pattern = re.compile(
        r"\b(OR|AND|SELECT|INSERT|DELETE|UPDATE|DROP|UNION|WHERE|EXEC|EXECUTE|ALTER|CREATE|TABLE|DATABASE|BENCHMARK|SLEEP)\b",
        flags=re.IGNORECASE
    )
    tokens_pattern = re.compile(r"(--|;|'|\"|#|\\)")

    # Recursive loop to prevent nested token bypasses
    for _ in range(10):
        prev = sanitized
        sanitized = tokens_pattern.sub("", sanitized)
        sanitized = keywords_pattern.sub("", sanitized)
        if sanitized == prev:
            break

    sanitized = re.sub(r"\s+", " ", sanitized)
    return sanitized.strip()


def sanitize_html_input(html_str: str) -> str:
    """
    Sanitize HTML input to prevent Cross-Site Scripting (XSS).
    - Neutralizes dangerous pseudo-protocols like 'javascript:', 'data:', 'vbscript:'.
    - Escapes all HTML special characters (<, >, &, \", ') into safe HTML entities.
    """
    if not isinstance(html_str, str):
        return ""

    cleaned = html_str.replace("\x00", "")
    # Neutralize dangerous executable URI schemes commonly used in href / src attributes
    cleaned = re.sub(r"(?i)(javascript|data|vbscript)\s*:", "blocked:", cleaned)
    return html.escape(cleaned, quote=True)
