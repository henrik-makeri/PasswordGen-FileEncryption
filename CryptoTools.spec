from PyInstaller.utils.hooks import collect_data_files, collect_submodules


project_root = SPECPATH

datas = []
datas += collect_data_files("wordfreq")
datas += collect_data_files("tkinterdnd2")

hiddenimports = []
hiddenimports += collect_submodules("wordfreq")
hiddenimports += collect_submodules("tkinterdnd2")


a = Analysis(
    [project_root + "\\crypto_tools\\gui_app.py"],
    pathex=[project_root],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
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
    [],
    exclude_binaries=True,
    name="CryptoTools",
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
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="CryptoTools",
)
