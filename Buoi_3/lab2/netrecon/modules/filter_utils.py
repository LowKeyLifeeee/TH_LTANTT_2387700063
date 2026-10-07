from .log_utils import log


def filter_targets(ip_list, whitelist=None, blacklist=None):
    whitelist = set(whitelist or [])
    blacklist = set(blacklist or [])
    result = []
    for ip in ip_list:
        if ip in blacklist or (whitelist and ip not in whitelist):
            log(f"Target excluded: {ip}")
            continue
        result.append(ip)
    return result
