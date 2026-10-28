@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 goto nopy

if not exist ".venv\Scripts\activate.bat" goto makeenv
goto runapp

:makeenv
echo Creating virtual environment (first run)...
python -m venv .venv
if errorlevel 1 goto venverr

:runapp
call ".venv\Scripts\activate.bat"
echo Installing dependencies (first run only, may take a minute)...
python -m pip install --upgrade pip
pip install -r requirements.txt
echo.
echo Starting MockLab at http://127.0.0.1:5000  (close this window to stop)
start "" http://127.0.0.1:5000
python app.py
echo.
echo Server stopped.
pause
exit /b 0

:nopy
echo.
echo   Python was not found on PATH.
echo   Install Python 3.11 or 3.12 from https://python.org
echo   and tick "Add Python to PATH" during install, then run this again.
echo.
pause
exit /b 1

:venverr
echo.
echo   Could not create the virtual environment.
echo   Make sure Python is installed correctly, then try again.
echo.
pause
exit /b 1
