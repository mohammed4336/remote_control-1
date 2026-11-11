@echo off
chcp 65001 >nul
cd /d "%~dp0"
title السيرفر الوسيط - اتركه شغال دائمًا
pip install -r requirements.txt
echo.
python relay_server.py
pause
