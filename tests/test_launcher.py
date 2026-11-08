import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import launcher

class LauncherTests(unittest.TestCase):
    def test_startup_failure_is_logged(self):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'startup.log'
            def failing():
                raise ModuleNotFoundError('simulated missing tkinter')
            self.assertEqual(launcher.run(failing,log),1)
            text=log.read_text(encoding='utf-8')
            self.assertIn('ModuleNotFoundError',text)
            self.assertIn('simulated missing tkinter',text)

    def test_normal_close(self):
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'startup.log'
            self.assertEqual(launcher.run(lambda:0,log),0)
            self.assertIn('Application closed normally',log.read_text(encoding='utf-8'))
