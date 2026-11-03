# build_windows.ps1 -- end-to-end build script for the NetLanvas
# Windows installer, mirroring packaging/macos/build_macos_pkg.sh's
# structure: Go helpers, PyInstaller binary, and Inno Setup packaging,
# all in one place. Run this ON WINDOWS, from a checkout of this
# repo's main branch, with Go, Python (+ a venv with requirements.txt
# + pyinstaller installed), Inno Setup, and git already available.
#
# Always cross^H^H^H natively compiles both Go helpers from whatever
# source is checked out RIGHT NOW -- never reuses a binary left over
# from a previous run. Same discipline as the macOS script, for the
# same reason (NATIVE-7's staleness incident).
#
# WinSW's own binary (netlanvas-service.exe) is NOT rebuilt here --
# it's a generic, version-independent third-party dependency, expected
# already staged at $WinSWPath (see -WinSWPath param).

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    [string]$WinSWPath = "C:\build-tools\winsw\netlanvas-service.exe"
)
$ErrorActionPreference = "Stop"

# Resolved relative to the script's own location -- packaging\windows,
# two levels below the repo root. Kept DIFFERENT from $BuildDir, same
# lesson as the macOS script: a self-copy of defaults.json onto itself
# fails fatally if the two ever resolve to the same path.
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$BuildDir = "C:\netlanvas-build"
$StageDir = Join-Path $PSScriptRoot "build"

# Native commands below (go build, PyInstaller, ISCC) routinely write
# informational banners to stderr, not just real errors -- over this
# SSH/PowerShell 5.1 setup specifically, $ErrorActionPreference="Stop"
# escalates ANY stderr line from a native command into a terminating
# exception immediately, aborting the whole script before the manual
# $LASTEXITCODE check below it ever runs (confirmed live 2026-11-03:
# PyInstaller's own startup banner line killed the script before it
# produced a fresh netlanvas.exe, silently leaving yesterday's stale
# build artifact in place). Each native call below is wrapped with a
# local 'Continue' override so stderr chatter can't do that -- the
# existing $LASTEXITCODE check immediately after each one remains the
# real correctness gate, unchanged. Script-wide $ErrorActionPreference
# stays "Stop" for everything else (Copy-Item, New-Item, etc.).
Write-Host "=== Building Go helpers (fresh, from current source) ==="
Push-Location (Join-Path $RepoRoot "tools\snmp_helper")
$ErrorActionPreference = "Continue"
go build -o (Join-Path $BuildDir "tools\snmp_helper\netlanvas_snmp_helper.exe") .
$ErrorActionPreference = "Stop"
if ($LASTEXITCODE -ne 0) { throw "snmp_helper build failed" }
Pop-Location

Push-Location (Join-Path $RepoRoot "tools\ping_sweep_helper")
$ErrorActionPreference = "Continue"
go build -o (Join-Path $BuildDir "tools\ping_sweep_helper\netlanvas_ping_sweep.exe") .
$ErrorActionPreference = "Stop"
if ($LASTEXITCODE -ne 0) { throw "ping_sweep_helper build failed" }
Pop-Location

Write-Host "=== Syncing app source into build dir ==="
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
# robocopy's /MIR mirrors (deletes anything in the destination that no
# longer exists in the source) -- the Windows equivalent of rsync -a
# --delete, which the macOS script relies on for the same reason: a
# removed source file must not silently survive in a stale build dir.
# Exit codes 0-7 are all success for robocopy; only >=8 is a real error.
robocopy "$RepoRoot\src" "$BuildDir\src" /MIR /NFL /NDL /NJH /NJS
if ($LASTEXITCODE -ge 8) { throw "robocopy src sync failed with code $LASTEXITCODE" }
Copy-Item -Force (Join-Path $RepoRoot "defaults.json") (Join-Path $BuildDir "defaults.json")

Write-Host "=== Building netlanvas.exe (PyInstaller) ==="
# Same PyInstaller spec-path-resolution gotcha as the macOS script:
# Analysis()/datas paths in the .spec resolve against the SPEC FILE'S
# OWN location, not the invocation cwd -- copy it into $BuildDir
# (where src/ and defaults.json actually live) before running it.
Copy-Item -Force (Join-Path $PSScriptRoot "netlanvas_windows.spec") (Join-Path $BuildDir "netlanvas_windows.spec")
Push-Location $BuildDir
$ErrorActionPreference = "Continue"
& "$BuildDir\venv\Scripts\pyinstaller.exe" netlanvas_windows.spec --noconfirm
$ErrorActionPreference = "Stop"
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed" }
Pop-Location

Write-Host "=== Staging build\ for Inno Setup ==="
if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
New-Item -ItemType Directory -Force -Path "$StageDir\ui" | Out-Null
New-Item -ItemType Directory -Force -Path "$StageDir\tools\ping_sweep_helper" | Out-Null
New-Item -ItemType Directory -Force -Path "$StageDir\tools\snmp_helper" | Out-Null

Copy-Item -Force "$BuildDir\dist\netlanvas.exe" "$StageDir\netlanvas.exe"
Copy-Item -Force $WinSWPath "$StageDir\netlanvas-service.exe"
Copy-Item -Force (Join-Path $PSScriptRoot "netlanvas-service.xml") "$StageDir\netlanvas-service.xml"
Copy-Item -Force (Join-Path $PSScriptRoot "stop-netlanvas.ps1") "$StageDir\stop-netlanvas.ps1"
robocopy "$BuildDir\src\ui" "$StageDir\ui" /E /NFL /NDL /NJH /NJS
if ($LASTEXITCODE -ge 8) { throw "robocopy ui stage failed with code $LASTEXITCODE" }
Copy-Item -Force "$BuildDir\tools\ping_sweep_helper\netlanvas_ping_sweep.exe" "$StageDir\tools\ping_sweep_helper\netlanvas_ping_sweep.exe"
Copy-Item -Force "$BuildDir\tools\snmp_helper\netlanvas_snmp_helper.exe" "$StageDir\tools\snmp_helper\netlanvas_snmp_helper.exe"

Write-Host "=== Building installer (Inno Setup) ==="
$ErrorActionPreference = "Continue"
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (Join-Path $PSScriptRoot "netlanvas.iss")
$ErrorActionPreference = "Stop"
if ($LASTEXITCODE -ne 0) { throw "ISCC build failed" }

$OutputExe = Join-Path $PSScriptRoot "Output\NetLanvas-Setup.exe"
$VersionedExe = Join-Path $PSScriptRoot "Output\NetLanvas-Setup-$Version.exe"
Move-Item -Force $OutputExe $VersionedExe
Write-Host "=== Done: $VersionedExe ==="
