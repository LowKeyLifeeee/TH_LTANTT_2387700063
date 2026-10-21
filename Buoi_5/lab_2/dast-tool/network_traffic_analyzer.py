import psutil


class NetworkTrafficAnalyzer:
    def get_network_stats(self):
        """Cumulative host counters per interface, not packet inspection."""
        return psutil.net_io_counters(pernic=True)
