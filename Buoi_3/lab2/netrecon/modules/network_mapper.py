import subprocess
from .log_utils import log


def map_network():
    log("Mapping network using local ARP table")
    try:
        result = subprocess.check_output(
            ["arp", "-a"], stderr=subprocess.STDOUT, timeout=15
        ).decode(errors="replace")
        log(result)
        return result
    except (OSError, subprocess.SubprocessError) as error:
        log(f"Network mapping failed: {error}")
        return f"Error: {error}"
