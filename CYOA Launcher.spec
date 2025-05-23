# CYOA Launcher.spec
# -*- mode: python ; coding: utf-8 -*-

import os
SPEC_DIR = os.path.dirname(os.path.abspath(__file__))

# Данные для всех платформ
a = Analysis(
    ['CYOA_Launcher.py'],
    pathex=[SPEC_DIR],
    binaries=[],
    datas=[], # Например: [('icon.png', '.')] если бы ты хотел PNG куда-то рядом положить
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False, # True для one-folder, False для упаковки в PYZ внутри EXE
    optimize=0,
)
pyz = PYZ(a.pure, name='pyz_archive')

# Базовая конфигурация EXE
exe_config = {
    'pyz': pyz,
    'scripts': a.scripts,
    'exclude_binaries': True, # Если не нужны специфичные бинарники из a.binaries
    'name': 'CYOA Launcher',
    'debug': False,
    'bootloader_ignore_signals': False,
    'strip': False, # Можно True для уменьшения размера
    'upx': True,    # Можно False если UPX не нужен или вызывает проблемы
    'console': False, # Эквивалент --windowed
    'disable_windowed_traceback': False,
    'argv_emulation': False,
    'target_arch': None,
    'codesign_identity': None,
    'entitlements_file': None,
}

# Платформо-специфичные настройки и сборка
# PyInstaller выполняет этот .spec файл, так что можно использовать Python логику
import sys
if sys.platform == 'win32':
    exe_config['icon'] = 'icon.ico'
    exe_instance = EXE(**exe_config)
    # Для Windows --onefile сборки COLLECT не определяет конечный результат,
    # сам EXE уже будет "одним файлом".
    # coll = COLLECT(exe_instance, a.binaries, a.datas, name='CYOA Launcher') # Для --onedir

elif sys.platform == 'darwin': # macOS
    # Для macOS, --onefile создаст исполняемый файл, который затем можно упаковать в .app
    # или можно сразу определить .app бандл.
    # Если нужен просто исполняемый файл (не .app), то BUNDLE не нужен.
    # Если нужен .app, то console=False в EXE и BUNDLE.
    exe_instance = EXE(**exe_config) # Исполняемый файл внутри .app
    app = BUNDLE(
        exe_instance,
        name='CYOA Launcher.app',
        icon='icon.icns',
        bundle_identifier=None # e.g., com.yourname.cyoalauncher
        # Тут могут быть и другие Info.plist настройки через `info_plist` параметр
    )
else: # Linux и другие
    exe_instance = EXE(**exe_config) # Иконка не ставится в сам исполняемый файл
    # coll = COLLECT(exe_instance, a.binaries, a.datas, name='CYOA Launcher') # Для --onedir