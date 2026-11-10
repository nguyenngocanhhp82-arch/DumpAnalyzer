# -*- mode: python ; coding: utf-8 -*-
# PyInstaller Spec File cho DumpAnalyzer
# Thiết lập:
# - Chế độ onedir (--onedir) giảm nguy cơ Antivirus báo nhầm và khởi động nhanh
# - Yêu cầu quyền Administrator (uac_admin=True) để đọc C:\Windows\Minidump
# - Không đóng gói thư mục config/ vào trong file nén mà giữ bên ngoài để IT sửa luật
# - Phân nhánh 2 file thực thi: DumpAnalyzer (GUI) và DumpAnalyzer-cli (CLI)

import sys
from pathlib import Path

block_cipher = None

SCHEMA_SQL = str(Path(SPECPATH) / 'src' / 'dumpanalyzer' / 'storage' / 'schema.sql')
CONFIG_DIR = str(Path(SPECPATH) / 'config')

# Analysis cho GUI (PySide6)
a_gui = Analysis(
    ['src/dumpanalyzer/gui/main.py'],
    pathex=['src'],
    binaries=[],
    datas=[(SCHEMA_SQL, 'dumpanalyzer/storage')],
    hiddenimports=[
        'openpyxl',
        'yaml',
        'jinja2',
        'PySide6',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'dumpanalyzer',
        'dumpanalyzer.gui',
        'dumpanalyzer.gui.theme',
        'dumpanalyzer.gui.tab_overview',
        'dumpanalyzer.gui.tab_detail',
        'dumpanalyzer.gui.tab_verdict',
        'dumpanalyzer.gui.tab_settings',
        'dumpanalyzer.gui.tab_hwtests',
        'dumpanalyzer.gui.main_window',
        'dumpanalyzer.gui.worker',
        'dumpanalyzer.engine.batch_analyzer',
        'dumpanalyzer.engine.fleet',
        'dumpanalyzer.analyzer.batch',
        'dumpanalyzer.report.exporter',
        'dumpanalyzer.hwtests',
        'dumpanalyzer.storage.db',
        'dumpanalyzer.collectors.sysinfo',
        'dumpanalyzer.collectors.asset_info',
        'dumpanalyzer.engine.deployment_package',
        'dumpanalyzer.gui.tab_dump_readiness',
        'dumpanalyzer.gui.tab_eventlog',
        'dumpanalyzer.analyzer.triage_reader',
        'dumpanalyzer.analyzer._selftest_fixture',
        'dumpanalyzer.engine.module_classifier',
        'dumpanalyzer.engine.triage_evaluator',
        'dumpanalyzer.analyzer.eventlog_analyzer',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'pandas', 'unittest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz_gui = PYZ(a_gui.pure, a_gui.zipped_data, cipher=block_cipher)

exe_gui = EXE(
    pyz_gui,
    a_gui.scripts,
    [],
    exclude_binaries=True,
    name='DumpAnalyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)

# Analysis cho CLI (Dòng lệnh console)
a_cli = Analysis(
    ['src/dumpanalyzer/cli.py'],
    pathex=['src'],
    binaries=[],
    datas=[(SCHEMA_SQL, 'dumpanalyzer/storage')],
    hiddenimports=[
        'openpyxl',
        'yaml',
        'jinja2',
        'dumpanalyzer',
        'dumpanalyzer.engine.batch_analyzer',
        'dumpanalyzer.engine.fleet',
        'dumpanalyzer.analyzer.batch',
        'dumpanalyzer.report.exporter',
        'dumpanalyzer.hwtests',
        'dumpanalyzer.storage.db',
        'dumpanalyzer.collectors.sysinfo',
        'dumpanalyzer.collectors.asset_info',
        'dumpanalyzer.collectors.dump_config',
        'dumpanalyzer.engine.deployment_package',
        'dumpanalyzer.analyzer.triage_reader',
        'dumpanalyzer.analyzer._selftest_fixture',
        'dumpanalyzer.engine.module_classifier',
        'dumpanalyzer.engine.triage_evaluator',
        'dumpanalyzer.analyzer.eventlog_analyzer',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'pandas', 'unittest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz_cli = PYZ(a_cli.pure, a_cli.zipped_data, cipher=block_cipher)

exe_cli = EXE(
    pyz_cli,
    a_cli.scripts,
    [],
    exclude_binaries=True,
    name='DumpAnalyzer-cli',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)

coll = COLLECT(
    exe_gui,
    exe_cli,
    a_gui.binaries,
    a_gui.zipfiles,
    a_gui.datas,
    a_cli.binaries,
    a_cli.zipfiles,
    a_cli.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='DumpAnalyzer',
)

# Analysis cho bản Portable 1 file duy nhất (tự động điều phối GUI và CLI)
a_portable = Analysis(
    ['src/dumpanalyzer/main_portable.py'],
    pathex=['src'],
    binaries=[],
    datas=[
        (SCHEMA_SQL, 'dumpanalyzer/storage'),
        (CONFIG_DIR, 'config'),
    ],
    hiddenimports=[
        'openpyxl',
        'yaml',
        'jinja2',
        'PySide6',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'dumpanalyzer',
        'dumpanalyzer.gui',
        'dumpanalyzer.gui.theme',
        'dumpanalyzer.gui.tab_overview',
        'dumpanalyzer.gui.tab_detail',
        'dumpanalyzer.gui.tab_verdict',
        'dumpanalyzer.gui.tab_settings',
        'dumpanalyzer.gui.tab_hwtests',
        'dumpanalyzer.gui.tab_dump_readiness',
        'dumpanalyzer.gui.tab_eventlog',
        'dumpanalyzer.gui.main_window',
        'dumpanalyzer.gui.worker',
        'dumpanalyzer.engine.batch_analyzer',
        'dumpanalyzer.engine.fleet',
        'dumpanalyzer.analyzer.batch',
        'dumpanalyzer.report.exporter',
        'dumpanalyzer.hwtests',
        'dumpanalyzer.storage.db',
        'dumpanalyzer.collectors.sysinfo',
        'dumpanalyzer.collectors.asset_info',
        'dumpanalyzer.collectors.dump_config',
        'dumpanalyzer.engine.deployment_package',
        'dumpanalyzer.analyzer.triage_reader',
        'dumpanalyzer.analyzer._selftest_fixture',
        'dumpanalyzer.engine.module_classifier',
        'dumpanalyzer.engine.triage_evaluator',
        'dumpanalyzer.analyzer.eventlog_analyzer',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'pandas', 'unittest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz_portable = PYZ(a_portable.pure, a_portable.zipped_data, cipher=block_cipher)

exe_portable = EXE(
    pyz_portable,
    a_portable.scripts,
    a_portable.binaries,
    a_portable.zipfiles,
    a_portable.datas,
    [],
    name='DumpAnalyzer-Portable',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)
