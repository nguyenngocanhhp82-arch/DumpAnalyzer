@echo off
chcp 65001 >nul
setlocal

:: ==============================================================================
:: DumpAnalyzer - Khởi chạy giao diện người dùng (GUI Runner)
:: ==============================================================================

set "PROJECT_ROOT=%~dp0"
cd /d "%PROJECT_ROOT%"

if exist "%PROJECT_ROOT%.venv\Scripts\python.exe" (
    set "PY_EXE=%PROJECT_ROOT%.venv\Scripts\python.exe"
) else (
    set "PY_EXE=python"
)

echo Đang khởi động giao diện DumpAnalyzer...
"%PY_EXE%" -m dumpanalyzer.gui.app %*
if errorlevel 1 (
    echo.
    echo [THÔNG BÁO] Giao diện đồ hoạ đang được xây dựng trong Phase 5.
    echo Hiện tại bạn có thể sử dụng dòng lệnh bằng file 'run_cli.bat'.
    echo.
    pause
)
endlocal
