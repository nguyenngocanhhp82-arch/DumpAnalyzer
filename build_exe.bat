@echo off
title Build DumpAnalyzer
cd /d "%~dp0"
echo =================================================================
echo         DANG DONG GOI DUMPANALYZER SANG FILE THUC THI .EXE
echo =================================================================
python build_exe.py
pause
