@echo off
title DNS Tunneling Detection Dashboard
cd /d "%~dp0"
echo ========================================================
echo   Launching DNS Tunneling Detection Dashboard...
echo ========================================================
call .\venv\Scripts\activate
streamlit run dashboard/app.py
pause
