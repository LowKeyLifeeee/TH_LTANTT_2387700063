import subprocess
import sys
import tempfile


class VirtualSandbox:
    """Temporary working directory demo, NOT an OS security boundary.

    Only the lab's echo command is supported; text is passed as an argument
    to a fixed Python program, never to a command shell.
    """
    def __init__(self):
        self._directory = tempfile.TemporaryDirectory(prefix='dast-lab-')
        self.temp_dir = self._directory.name

    def run_isolated(self, command):
        if not isinstance(command, str) or len(command) > 4096:
            raise ValueError('command must be a string of at most 4096 characters')
        parts = command.strip().split(maxsplit=1)
        if not parts or parts[0] != 'echo':
            raise ValueError('Only echo <text> is supported by this demo')
        message = parts[1] if len(parts) == 2 else ''
        result = subprocess.run(
            [sys.executable, '-I', '-X', 'utf8', '-c',
             'import sys; print(sys.argv[1])', message],
            cwd=self.temp_dir, capture_output=True, text=True,
            encoding='utf-8', shell=False, timeout=5, check=True,
        )
        return result.stdout, result.stderr

    def close(self):
        self._directory.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
