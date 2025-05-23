# CYOA Launcher.spec
# -*- mode: python ; coding: utf-8 -*-

import os
import sys # Required for sys.platform

# Determine the directory of this .spec file.
# PyInstaller provides 'SPECPATH'. If not available (e.g. running spec directly), fallback.
try:
    SPEC_DIR = SPECPATH
except NameError:
    SPEC_DIR = os.path.dirname(os.path.abspath(__file__)) # Fallback, might not work in all PyInstaller contexts

a = Analysis(
    ['CYOA_Launcher.py'], # Main application script
    pathex=[SPEC_DIR],    # Add current directory to Python's search path for modules
    binaries=[],          # List of non-python libraries to include (e.g., .dll, .so)
    datas=[],             # List of data files to include (e.g., images, config files)
                          # Format: [('source_file_path', 'destination_in_bundle'), ...]
    hiddenimports=[],     # List of modules not automatically detected by PyInstaller
    hookspath=[],         # List of paths to custom PyInstaller hooks
    hooksconfig={},       # Configuration for hooks
    runtime_hooks=[],     # List of scripts to run at runtime before your main script
    excludes=[],          # List of modules to exclude from the build
    noarchive=False,      # False: bundle .pyc files into a PYZ archive inside the executable
                          # True:  leave .pyc files as is (mostly for one-folder builds)
    optimize=0,           # Python bytecode optimization level (0, 1, or 2)
)
pyz = PYZ(a.pure, name='pyz_archive') # a.pure contains all discovered Python modules

# --- Common EXE configuration ---
# These settings will be used to build the executable file.
# For macOS, this executable will be placed inside the .app bundle.
exe_base_config = {
    'pyz': pyz,
    'scripts': a.scripts, # Usually contains only the main script (CYOA_Launcher.py)
    # 'a.binaries' and 'a.datas' are automatically included if not overridden
    'name': 'CYOA Launcher', # Base name for the executable
    'debug': False,          # Enable/disable debug mode for the bootloader
    'bootloader_ignore_signals': False,
    'strip': False,          # Strip symbols from executable and shared libs (True for smaller size)
    'upx': True,             # Use UPX to compress (if available and desired)
    'console': False,        # False for a GUI application (no console window)
    'disable_windowed_traceback': False, # For GUI apps on Windows
    'argv_emulation': False, # Emulate argv passing on macOS .app launch
    'target_arch': None,     # None for current architecture, or specify (e.g., 'x86_64', 'arm64')
    'codesign_identity': None, # For macOS code signing
    'entitlements_file': None, # For macOS entitlements
}

# --- Platform-specific EXE/BUNDLE generation ---
if sys.platform == 'win32':
    # Windows-specific settings
    exe_config_win = exe_base_config.copy()
    exe_config_win['icon'] = 'icon.ico'
    exe = EXE(**exe_config_win)
    # For --onefile on Windows, the EXE itself is the final product.
    # The COLLECT object below is more relevant for --onedir builds.
    # If you were doing --onedir, you'd use 'coll' as the target.

elif sys.platform == 'darwin': # macOS
    # macOS-specific settings
    exe_config_mac = exe_base_config.copy()
    # The icon for the .app bundle is specified in BUNDLE, not usually in the internal EXE.
    exe_for_bundle = EXE(**exe_config_mac)

    app = BUNDLE(
        exe_for_bundle,
        name='CYOA Launcher.app', # The name of the .app bundle
        icon='icon.icns',         # Path to the .icns icon file
        bundle_identifier=None,   # Optional: e.g., 'com.yourname.cyoalauncher'
        # info_plist={'NSHighResolutionCapable': 'True'}, # Example Info.plist customization
        # datas=a.datas # If you need to copy data files into Contents/Resources
    )

else: # Linux and other Unix-like systems
    # Linux-specific settings (icon is not part of the executable itself)
    exe_config_linux = exe_base_config.copy()
    exe = EXE(**exe_config_linux)
    # Similar to Windows, for --onefile, EXE is the product.
    # coll = COLLECT(exe, a.binaries, a.datas, name='CYOA Launcher') # For --onedir

# Note: When using 'pyinstaller --onefile your.spec', PyInstaller processes the EXE
# (and BUNDLE for macOS) definition to create a single distributable file or .app.
# The 'COLLECT' object is primarily for --onedir (one-folder) builds, defining the
# structure of that output folder. For --onefile, PyInstaller effectively
# "collects" into the single executable.