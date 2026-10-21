from pathlib import Path


class SecurityBehaviorChecker:
    def suspicious_calls(self, source_path=None):
        """Reproduce the lab's textual heuristic; this is NOT runtime tracing.

        With no target, scan this module as in the supplied example. The rule
        literals themselves produce matches, so these are not proven calls.
        """
        content = Path(source_path or __file__).read_text(encoding='utf-8')
        return [call for call in ('os.system', 'eval', 'exec') if call in content]
