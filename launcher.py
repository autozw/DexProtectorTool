"""Keep startup failures visible and save Python/native diagnostics."""
import contextlib
import faulthandler
from pathlib import Path
import platform
import sys
import tempfile
import time
import traceback

class Tee:
    def __init__(self, console, log):
        self.console, self.log = console, log
    def write(self, text):
        self.log.write(text)
        self.log.flush()
        if self.console is not None:
            try:
                self.console.write(text)
                self.console.flush()
            except (OSError, UnicodeError):
                self.console = None
        return len(text)
    def flush(self):
        self.log.flush()
        if self.console is not None:
            try:
                self.console.flush()
            except OSError:
                self.console = None

def run(entry=None, log_path=None):
    path = Path(log_path) if log_path else Path(__file__).resolve().parent/'startup.log'
    try:
        log = path.open('a',encoding='utf-8')
    except OSError:
        path = Path(tempfile.gettempdir())/'DexProtectorTool-startup.log'
        log = path.open('a',encoding='utf-8')
    with log, contextlib.redirect_stdout(Tee(sys.stdout,log)), contextlib.redirect_stderr(Tee(sys.stderr,log)):
        print('\n'+time.strftime('%Y-%m-%d %H:%M:%S')+'  Starting DexProtectorTool')
        print('Python:',sys.executable)
        print('Version:',sys.version.split()[0], 'Bits:',64 if sys.maxsize>2**32 else 32)
        print('Windows/platform:',platform.platform())
        print('Startup log:',path)
        previous = faulthandler.is_enabled()
        if not previous:
            faulthandler.enable(file=log)
        try:
            if entry is None:
                from app import main
                entry = main
            result = entry()
            print('Application closed normally.')
            return int(result or 0)
        except Exception:
            traceback.print_exc()
            print('Startup failed. Full details were saved to:',path)
            return 1
        finally:
            if not previous:
                faulthandler.disable()

if __name__=='__main__':
    raise SystemExit(run())
