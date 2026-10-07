import socket
from .log_utils import log


def grab_banner(ip, port):
    log(f"Banner request {ip}:{port}")
    try:
        with socket.create_connection((ip, port), timeout=2) as connection:
            banner = connection.recv(1024).decode("utf-8", errors="replace").strip()
        log(f"Banner result {ip}:{port}: {banner!r}")
        return banner
    except OSError as error:
        log(f"Banner failed {ip}:{port}: {error}")
        return f"Failed to grab banner: {error}"
