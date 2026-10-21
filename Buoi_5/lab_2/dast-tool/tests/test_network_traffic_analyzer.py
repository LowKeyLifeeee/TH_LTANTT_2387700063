import unittest
from network_traffic_analyzer import NetworkTrafficAnalyzer


class TestNetworkTrafficAnalyzer(unittest.TestCase):
    def test_get_network_stats(self):
        stats = NetworkTrafficAnalyzer().get_network_stats()
        self.assertIsInstance(stats, dict)
        for stat in stats.values():
            self.assertGreaterEqual(stat.bytes_sent, 0)
            self.assertGreaterEqual(stat.bytes_recv, 0)
