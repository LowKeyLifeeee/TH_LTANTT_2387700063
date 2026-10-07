import asyncio
import ipaddress
import time
from .port_scanner import async_scan_ports
from .banner_grabber import grab_banner
from .service_detector import detect_service
from .network_mapper import map_network
from .vuln_checker import check_vulns
from .filter_utils import filter_targets
from .log_utils import log

DEFAULT_EMAIL = "thangminhnt20@gmail.com"
MODES = {"all", "scan", "service", "banner", "map", "vuln"}


def validate_target(target):
    target = target.strip()
    if not target:
        raise ValueError("Bạn chưa nhập Target IP. Ví dụ: 127.0.0.1.")
    if len(target.split()) > 1 or "," in target:
        raise ValueError("Target IP chỉ nhận một IP mỗi lần. Nhập riêng từng địa chỉ rồi chạy Scan.")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError as error:
        raise ValueError(
            "Target IP không hợp lệ. Nhập IPv4 hoặc IPv6, ví dụ 127.0.0.1; "
            "không kèm http://, tên miền hoặc số cổng."
        ) from error


def parse_ports(value):
    ports = set()
    try:
        for part in value.split(","):
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                if not 1 <= start <= end <= 65535 or end - start >= 1024:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        if not ports or len(ports) > 1024 or any(not 1 <= port <= 65535 for port in ports):
            raise ValueError
    except ValueError as error:
        raise ValueError("Cong phai thuoc 1..65535, toi da 1024 cong moi lan.") from error
    return sorted(ports)


def run_task(target, ports, mode="all", rate_limit=10, whitelist=None, blacklist=None):
    target = validate_target(target)
    if mode not in MODES:
        raise ValueError("Mode khong hop le.")
    if not 0.1 <= rate_limit <= 100:
        raise ValueError("Rate limit phai tu 0.1 den 100 ket noi/giay.")
    def validate_filter(values, field):
        result = []
        for ip in values or []:
            try:
                result.append(validate_target(ip))
            except ValueError as error:
                raise ValueError(
                    f'{field}: "{ip}" không phải địa chỉ IP hợp lệ. '
                    "Chỉ nhập IP cách nhau bằng khoảng trắng hoặc để trống ô này."
                ) from error
        return result

    whitelist = validate_filter(whitelist, "Whitelist")
    blacklist = validate_filter(blacklist, "Blacklist")
    if not filter_targets([target], whitelist, blacklist):
        raise ValueError("Muc tieu bi chan boi whitelist/blacklist.")
    log(f"Task started target={target} mode={mode} ports={ports} rate={rate_limit}")
    result = {}
    if mode in ("scan", "all"):
        result["scan"] = asyncio.run(async_scan_ports(target, ports, rate_limit))
    if mode in ("service", "all"):
        result["service"] = detect_service(target, ports, rate_limit)
    if mode in ("banner", "all"):
        result["banner"] = {}
        for index, port in enumerate(ports):
            if index:
                time.sleep(1 / rate_limit)
            result["banner"][port] = grab_banner(target, port)
    if mode in ("map", "all"):
        result["map"] = map_network()
    if mode in ("vuln", "all"):
        result["vuln"] = check_vulns(result.get("scan", ports))
    log(f"Task completed target={target} mode={mode}")
    return result
