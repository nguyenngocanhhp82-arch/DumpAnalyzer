@echo off
chcp 65001 >nul
setlocal

:: ==============================================================================
:: DumpAnalyzer - Khởi chạy dòng lệnh (CLI Runner)
:: ==============================================================================

set "PROJECT_ROOT=%~dp0"
cd /d "%PROJECT_ROOT%"

:: Kiểm tra môi trường ảo .venv nếu có
if exist "%PROJECT_ROOT%.venv\Scripts\python.exe" (
    set "PY_EXE=%PROJECT_ROOT%.venv\Scripts\python.exe"
) else (
    set "PY_EXE=python"
)

:: Nếu không truyền tham số, mặc định chạy lệnh kiểm tra môi trường check-env
if "%~1"=="" (
    echo Đang chạy kiểm tra môi trường hệ thống...
    "%PY_EXE%" -m dumpanalyzer.cli check-env
    pause
    exit /b 0
)

"%PY_EXE%" -m dumpanalyzer.cli %*
if errorlevel 1 (
    echo.
    echo [LỖI] Lệnh thực thi thất bại hoặc bị huỷ.
)
endlocal
