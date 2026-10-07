import subprocess
from .log_utils import log


def detect_service(ip, ports, rate_limit=10):
    ports = [int(port) for port in ports]
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Provide ports in range 1..65535")
    ports_str = ",".join(map(str, ports))
    command = ["nmap", "-sV", "--max-rate", str(rate_limit), "-p", ports_str, "--", ip]
    log(f"Running service detection on {ip}:{ports_str}")
    try:
        result = subprocess.check_output(
            command, stderr=subprocess.STDOUT, timeout=120
        ).decode(errors="replace")
        log(result)
        return result
    except (OSError, subprocess.SubprocessError) as error:
        log(f"Service detection failed: {error}")
        return f"Error: {error}"
