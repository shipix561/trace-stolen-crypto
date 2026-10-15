@echo off
chcp 65001 >nul
cd /d "%~dp0"
python labels_tool.py sync
python labels_tool.py stats
pause
