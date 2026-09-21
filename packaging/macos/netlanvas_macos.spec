# -*- mode: python ; coding: utf-8 -*-
# Phase 6 (macOS): mirrors packaging's Windows netlanvas.spec exactly --
# same onefile/console/hidden-import shape, just macOS paths and
# target_arch='arm64' (arm64-only build, per the Phase 6 open-questions
# review -- no Intel Mac support planned).
#
# Paths are relative to THIS FILE'S OWN DIRECTORY (PyInstaller resolves
# spec-relative Analysis()/datas paths against the spec's location, not
# the invocation cwd, regardless of the cwd build_macos_pkg.sh sets) --
# so that script copies this spec into its build dir (alongside the
# freshly rsynced src/ and defaults.json) before running PyInstaller on
# it, rather than running it in place from packaging/macos/. Confirmed
# live 2026-09-02 after the original cwd-relative assumption here was
# found to be wrong -- running PyInstaller straight off this file's
# repo location fails with "script '.../packaging/macos/src/main.py'
# not found". Keep these paths relative (don't hardcode a machine-
# specific absolute path); just remember they resolve against wherever
# THIS FILE sits at invocation time, which must be the build dir.
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
    target_arch='arm64',
    codesign_identity=None,
    entitlements_file=None,
)
