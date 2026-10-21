from pathlib import Path
import unittest
from virtual_sandbox import VirtualSandbox


class TestVirtualSandbox(unittest.TestCase):
    def test_echo_and_cleanup(self):
        with VirtualSandbox() as vs:
            directory = Path(vs.temp_dir)
            self.assertTrue(directory.is_dir())
            self.assertEqual(vs.run_isolated('echo test'), ('test\n', ''))
        self.assertFalse(directory.exists())

    def test_shell_characters_are_literal(self):
        with VirtualSandbox() as vs:
            text = 'hello & whoami | echo nope > file.txt'
            self.assertEqual(vs.run_isolated('echo '+text), (text+'\n', ''))
            self.assertEqual(list(Path(vs.temp_dir).iterdir()), [])

    def test_invalid_commands(self):
        with VirtualSandbox() as vs:
            for command in (None, [], '', 'whoami', 'python app.py', 'echo '+'a'*4096):
                with self.assertRaises(ValueError):
                    vs.run_isolated(command)
