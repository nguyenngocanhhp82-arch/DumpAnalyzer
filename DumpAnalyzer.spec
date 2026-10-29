# -*- mode: python ; coding: utf-8 -*-
"""
DumpAnalyzer PyInstaller Specification File
Cấu hình đóng gói DumpAnalyzer theo chuẩn UPDATE_01:
- Dạng thư mục (--onedir), khởi động nhanh, ít bị diệt virus quét nhầm.
- Giao diện cửa sổ (--windowed).
- Tự yêu cầu quyền Administrator (--uac-admin).
- KHÔNG nhúng thư mục config/ vào file thực thi; thư mục config/ được đặt ngay bên cạnh .exe
  để kỹ thuật viên IT có thể chỉnh sửa quy tắc YAML trực tiếp mà không cần build lại.
- KHÔNG kèm cdb.exe (người dùng tự cài Debugging Tools for Windows).
"""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

project_root = Path.cwd().resolve()
src_path = str(project_root / "src")

hidden_imports = [
    "dumpanalyzer",
    "dumpanalyzer.cli",
    "dumpanalyzer.analyzer.batch",
    "dumpanalyzer.analyzer.cdb_parser",
    "dumpanalyzer.analyzer.cdb_runner",
    "dumpanalyzer.analyzer.header_parser",
    "dumpanalyzer.collectors.dump_finder",
    "dumpanalyzer.collectors.dump_config",
    "dumpanalyzer.collectors.eventlog",
    "dumpanalyzer.collectors.hardware",
    "dumpanalyzer.collectors.drivers_updates",
    "dumpanalyzer.core.config",
    "dumpanalyzer.core.db",
    "dumpanalyzer.core.logging_setup",
    "dumpanalyzer.core.models",
    "dumpanalyzer.core.timeutil",
    "dumpanalyzer.engine.correlator",
    "dumpanalyzer.engine.rule_loader",
    "dumpanalyzer.engine.scorer",
    "dumpanalyzer.engine.verdict",
    "dumpanalyzer.gui.main_window",
    "dumpanalyzer.gui.tab_overview",
    "dumpanalyzer.gui.tab_detail",
    "dumpanalyzer.gui.tab_verdict",
    "dumpanalyzer.gui.tab_settings",
    "dumpanalyzer.gui.theme",
    "dumpanalyzer.gui.worker",
    "dumpanalyzer.report.exporter",
    "openpyxl",
    "yaml",
]

# Thu thập toàn bộ submodule bổ sung của PySide6 nếu cần
hidden_imports += collect_submodules("PySide6")

a = Analysis(
    [str(project_root / "src" / "dumpanalyzer" / "gui" / "main.py")],
    pathex=[src_path],
    binaries=[],
    datas=[],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "notebook"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="DumpAnalyzer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # --windowed
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,  # --uac-admin (Yêu cầu quyền Administrator)
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="DumpAnalyzer",
)
