# stop-netlanvas.ps1
#
# NATIVE-17 (2026-09-04): stops the NetLanvas service and waits for its
# real process tree to actually exit, before the caller (the installer,
# on either a fresh install/upgrade via PrepareToInstall or an uninstall
# via [UninstallRun]) touches any of its files.
#
# Confirmed live: WinSW's "stop" CLI prints "stopped successfully" and
# returns as soon as the stop REQUEST is acknowledged -- the Service
# Control Manager reports STOP_PENDING at that exact instant, with
# every netlanvas.exe/helper process still fully running. The real
# shutdown (netlanvas.exe's own cleanup, tearing down its Go helper
# subprocess) took up to ~8s in testing. A fixed multi-second pause
# elsewhere in this installer had been intermittently too short for
# this for 7+ releases -- this was never a WinSW process-tree-tracking
# bug, just a fixed-duration guess losing a race against a genuinely
# variable-duration shutdown. Poll for real completion instead, with a
# force-kill fallback as a final safety net if something still hasn't
# exited after a generous timeout.
#
# Also covers the case an in-place reinstall/upgrade never used to:
# launching a NEW installer over an already-installed NetLanvas (same
# AppId) never runs the OLD version's [UninstallRun] steps -- those
# only fire via the Control Panel / unins000.exe uninstall path -- so
# without this running from PrepareToInstall too, [Files] would try to
# overwrite netlanvas.exe while the previous install's service was
# still fully running, and DeleteFile would fail with access denied.

$ErrorActionPreference = 'SilentlyContinue'

$serviceExe = Join-Path $PSScriptRoot 'netlanvas-service.exe'
if ((Get-Service -Name NetLanvas) -and (Test-Path $serviceExe)) {
    & $serviceExe stop | Out-Null
}

$procNames = 'netlanvas', 'netlanvas-service', 'netlanvas_snmp_helper', 'netlanvas_ping_sweep'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
while ((Get-Process -Name $procNames) -and $sw.Elapsed.TotalSeconds -lt 30) {
    Start-Sleep -Milliseconds 500
}

Get-Process -Name $procNames | Stop-Process -Force
