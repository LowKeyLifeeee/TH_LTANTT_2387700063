import gc


class MemoryAnalyzer:
    def check_memory_leaks(self):
        """Return GC garbage with finalizers, not a complete leak detector."""
        gc.collect()
        return [obj for obj in gc.garbage if hasattr(obj, '__del__')]

    def check_overflow(self, value):
        """Check signed 64-bit range; Python integers themselves do not overflow."""
        return type(value) is int and not -(2**63) <= value < 2**63
