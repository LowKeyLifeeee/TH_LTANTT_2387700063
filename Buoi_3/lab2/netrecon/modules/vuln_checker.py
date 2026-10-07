from .log_utils import log

# Danh sach minh hoa tu bai thuc hanh, khong xac nhan CVE qua so cong.
VULN_PORTS = {
    21: "FTP - CVE-2015-3306, CVE-2001-0261",
    22: "SSH - CVE-2018-15473",
    23: "Telnet - CVE-2011-4862",
    80: "HTTP - CVE-2021-41773",
    443: "HTTPS - CVE-2021-3449",
}


def check_vulns(ports):
    """Tra cuu goi y; can kiem tra san pham/phien ban de xac nhan."""
    result = {port: VULN_PORTS[port] for port in ports if port in VULN_PORTS}
    log(f"Basic vulnerability hints (unverified): {result}")
    return result
