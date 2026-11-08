@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto use_python
py -3.12 -c "import sys" >nul 2>nul
if errorlevel 1 goto use_python
py -3.12 -m venv .venv
if errorlevel 1 goto failed
goto install
:use_python
python -c "import sys; assert (3,10) <= sys.version_info[:2] < (3,14) and sys.maxsize > 2**32" >nul 2>nul
if errorlevel 1 goto failed
python -m venv .venv
if errorlevel 1 goto failed
:install
if not exist ".venv\Scripts\python.exe" goto failed
".venv\Scripts\python.exe" -m pip install --no-deps -r requirements.txt
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -c "import tkinter,elftools,unicorn,cryptography,numpy,zstandard,loguru; from androguard.core.dex import DEX; import engine"
if errorlevel 1 goto failed
echo Installation complete. Run start.bat.
pause
exit /b 0
:failed
echo Installation failed. Install Python 3.12 x64 with Tcl/Tk, then check the errors above.
pause
exit /b 1
