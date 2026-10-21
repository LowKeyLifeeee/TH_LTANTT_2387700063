import unittest
from unittest.mock import patch
from memory_analyzer import MemoryAnalyzer


class TestMemoryAnalyzer(unittest.TestCase):
    def test_overflow_boundaries(self):
        ma = MemoryAnalyzer()
        for value in (2**64, 2**63, -(2**63)-1):
            self.assertTrue(ma.check_overflow(value))
        for value in (100, 2**63-1, -(2**63), True, 'large', None):
            self.assertFalse(ma.check_overflow(value))

    def test_garbage_filter(self):
        class Finalizer:
            def __del__(self):
                pass
        obj = Finalizer()
        with patch('memory_analyzer.gc.collect'), patch('memory_analyzer.gc.garbage', [obj, object()]):
            self.assertEqual(MemoryAnalyzer().check_memory_leaks(), [obj])
