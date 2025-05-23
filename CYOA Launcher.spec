# CYOA Launcher.spec
# -*- mode: python ; coding: utf-8 -*-

# Ensure the directory containing this spec file (and your scripts) is in pathex
import os
SPEC_DIR = os.path.dirname(os.path.abspath(__file__))

a = Analysis(
    ['CYOA_Launcher.py'], # Main script
    pathex=[SPEC_DIR],    # Explicitly add the directory of the spec file to search paths
    binaries=[],
    datas=[],             # If you had other data files, they'd go here (e.g., ('icon.png', '.'))
    hiddenimports=[],     # For imports PyInstaller might miss (e.g., from plugins)
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,      # False to archive into .pyz, True for one-folder build primarily
    optimize=0,           # No bytecode optimization by default
)
pyz = PYZ(a.pure, name='pyz_archive') # a.pure contains your CYOA_Launcher.pyc, project_downloader.pyc, etc.

exe = EXE(
    pyz,
    a.scripts,            # Usually just the main script, others are in pyz
    # binaries and datas from Analysis are automatically included if not overridden here
    name='CYOA Launcher', # Name of the output executable
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,          # Set to True to strip symbols (makes slightly smaller, harder to debug)
    upx=True,             # Set to False if UPX causes issues or is not available
    console=False,        # True for console app, False for windowed (GUI) app
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,     # None for current architecture
    codesign_identity=None,
    entitlements_file=None,
    # icon parameter can be set here, but it's platform-specific.
    # It's often easier to manage via CLI options in the CI matrix for different OS.
    # For example, for Windows: icon='icon.ico'
)

# For a single-file executable, 'coll' (COLLECT) is not directly used for the final output,
# but PyInstaller uses its structure internally when building the single file.
# If you were building a one-folder app (--onedir), then 'coll' would define that output folder.
coll = COLLECT( # This part is more relevant for --onedir builds
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    name='CYOA Launcher_collected_files', # Name of the folder if it was a one-dir build
)

# For macOS .app bundle, you would uncomment and configure this:
# app = BUNDLE(
#     exe,
#     name='CYOA Launcher.app',
#     icon='icon.icns', # macOS specific icon
#     bundle_identifier=None # e.g., 'com.yourusername.cyoalauncher'
# )