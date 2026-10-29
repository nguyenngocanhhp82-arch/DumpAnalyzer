@echo off
chcp 65001 > nul
echo =================================================================
echo       DUMPANALYZER — TIẾN TRÌNH ĐÓNG GÓI FILE .EXE (PYINSTALLER)
echo =================================================================

cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo [*] Đang sử dụng Python: %PYTHON_EXE%
%PYTHON_EXE% -m pip install pyinstaller openpyxl PySide6 pyyaml --quiet

echo [*] Đang khởi chạy script build...
%PYTHON_EXE% scripts\build_exe.py

if %ERRORLEVEL% equ 0 (
    echo.
    echo [OK] ĐÓNG GÓI HOÀN TẤT!
    echo Vui lòng kiểm tra thư mục 'dist\DumpAnalyzer\'
) else (
    echo.
    echo [ERROR] Quá trình đóng gói thất bại với mã lỗi %ERRORLEVEL%
)

pause
