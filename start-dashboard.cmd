@echo off
cd /d "%~dp0"
echo Dashboard folder: %CD%
echo Checking Python and dependencies...
python --version
if errorlevel 1 goto failed
python -c "import yaml"
if errorlevel 1 (
  echo Installing project requirements...
  python -m pip install -r requirements.txt
  if errorlevel 1 goto failed
)
echo Open http://127.0.0.1:8000/ in your browser after the Local dashboard message.
echo Keep this window open while using the dashboard.
python -m dashboard.app
if errorlevel 1 goto failed
goto end
:failed
echo.
echo Dashboard could not start. Please copy the error above into the chat.
:end
pause
