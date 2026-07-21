# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\Pc\\Desktop\\projects\\stage\\ai_network_copilot\\launcher.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\Pc\\Desktop\\projects\\stage\\ai_network_copilot\\version.txt', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='AI-Network-Copilot',
    icon='C:\\Users\\Pc\\Desktop\\projects\\stage\\ai_network_copilot\\dashboard\\static\\app-icon.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
