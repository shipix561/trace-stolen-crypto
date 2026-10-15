@echo off
cd /d "%~dp0"
where python >nul 2>nul && (python serve.py) || (py serve.py)
pause
