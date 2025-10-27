# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for scan_port_gui
import os

block_cipher = None

project_root = os.path.abspath(os.path.dirname(__file__))

# Add data files as tuples: (source_path, dest_relative_dir)
# Example: datas = [ (os.path.join(project_root, 'examples.sh'), '.') ]
datas = []

hiddenimports = []

a = Analysis(
    ['gui_port_scanner.py'],
    pathex=[project_root],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='scan_port_gui',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # GUI app (no console window on Windows)
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='scan_port_gui',
)
