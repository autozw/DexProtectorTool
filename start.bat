@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto venv
where py >nul 2>nul
if errorlevel 1 goto system_python
py -3.12 -c "import sys" >nul 2>nul
if errorlevel 1 goto system_python
py -3.12 -u "%~dp0launcher.py"
goto finished
:system_python
where python >nul 2>nul
if errorlevel 1 goto no_python
python -u "%~dp0launcher.py"
goto finished
:venv
".venv\Scripts\python.exe" -u "%~dp0launcher.py"
:finished
if errorlevel 1 goto failed
exit /b 0
:no_python
echo Python was not found. Install Python 3.12 x64, then run install.bat.
goto wait_exit
:failed
echo.
echo Startup failed. Read the error above and startup.log in this folder.
echo If dependencies are missing, run install.bat first.
:wait_exit
pause
exit /b 1
