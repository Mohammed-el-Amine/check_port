# -*- mode: python ; coding: utf-8 -*-
import sys
import os

icon = None
if sys.platform.startswith("win"):
    icon = "assets/icon.ico"
elif sys.platform == "darwin":
    icon = "assets/icon.icns"
else:
    icon = "assets/icon.png"
if icon and not os.path.exists(icon):
    icon = None

a = Analysis(
    ['gui_qt.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'probes', 'enrich', 'async_scanner', 'check_port',
        'PySide6.QtCore', 'PySide6.QtGui', 'PySide6.QtWidgets',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'matplotlib', 'numpy', 'pandas',
        'PySide6.QtNetwork', 'PySide6.QtQml', 'PySide6.QtWebEngineCore',
        'PySide6.QtMultimedia', 'PySide6.Qt3DCore',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='scan_port_gui',
    debug=False,
    icon=icon,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,   # UPX casse parfois les binaires PySide6 sur Windows
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
