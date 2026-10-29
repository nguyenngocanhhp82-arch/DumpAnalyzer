@echo off
REM ============================================================
REM  Chay-EventLogAnalyzer.bat
REM  Double-click file nay de mo ung dung giao dien phan tich
REM  Windows Event Log (Dump / Reset / Khoi dong lai bat thuong).
REM  Tu dong xin quyen Admin.
REM ============================================================

net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo Dang xin quyen Admin, vui long bam "Yes" o cua so hien ra...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
start "" powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0EventLogAnalyzer.ps1"
