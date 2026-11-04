# -*- mode: python ; coding: utf-8 -*-
# Recreated 2026-11-02 for the current Windows build machine -- same
# onefile/console/hidden-import shape as packaging/macos/netlanvas_macos.spec
# (itself modeled on this file's original, never-committed ancestor at
# C:\netlanvas-win-spike\netlanvas.spec on the old build machine). No
# target_arch/codesign/entitlements -- those are macOS-only EXE() args.
#
# Paths are relative to THIS FILE'S OWN DIRECTORY (PyInstaller resolves
# spec-relative Analysis()/datas paths against the spec's location, not
# the invocation cwd) -- so the build script copies this spec into its
# build dir (alongside the freshly synced src/ and defaults.json) before
# running PyInstaller on it, rather than running it in place from
# packaging/windows/.
from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.utils.hooks import collect_all

datas = [('defaults.json', '.')]
binaries = []
hiddenimports = ['api.server']
hiddenimports += collect_submodules('api')
tmp_ret = collect_all('pysnmp')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('zeroconf')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['src/main.py'],
    pathex=[],
    binaries=binaries,
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
    a.binaries,
    a.datas,
    [],
    name='netlanvas',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
)
