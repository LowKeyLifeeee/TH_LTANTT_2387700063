"""Inspect the syntax tree without executing the input program."""

import ast


class ASTAnalyzer:
    def analyze(self, code: str):
        tree = ast.parse(code)
        lines = code.splitlines()
        issues = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", "")
            if name not in {"eval", "exec"}:
                continue
            # Python AST columns count UTF-8 bytes; SARIF uses characters.
            prefix = lines[node.lineno - 1].encode("utf-8")[:node.col_offset]
            issues.append({
                "type": f"Use of {name}",
                "message": (
                    f"Use of {name}() is dangerous and should be avoided."
                ),
                "lineno": node.lineno,
                "col_offset": len(prefix.decode("utf-8")),
            })
        return issues
