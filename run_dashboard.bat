@echo off
title Sniffsense Web Dashboard
cd /d "%~dp0"
echo ========================================================
echo         Launching Sniffsense Web Dashboard
echo ========================================================
echo.
echo Opening browser to http://localhost:5000 ...
start http://localhost:5000
echo Starting dashboard server...
.venv\Scripts\python.exe web_dashboard.py 5000
pause

