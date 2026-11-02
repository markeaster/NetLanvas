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
#
# NATIVE-19 (2026-10-21): two real bugs found live during a Windows
# machine retirement uninstall, both confirmed on real hardware:
#
# 1. `& $serviceExe stop | Out-Null` below used to have no timeout of
#    its own. If the app's own graceful shutdown wedges (the same class
#    of issue as main.py's BUG-24 streaming-response wedge -- whose own
#    5s internal os._exit(1) fallback evidently didn't save this run),
#    that call blocks indefinitely, and the 30s poll+force-kill safety
#    net further down never even runs, since it was sequenced after a
#    call with no bound of its own. Confirmed live: an uninstall sat
#    for 6+ hours with the service's processes at near-zero CPU before
#    anyone noticed. Fixed by running the stop in a background job with
#    an explicit timeout instead of blocking inline.
#
# 2. netlanvas-service.xml's <onfailure action="restart"> means Windows'
#    Service Control Manager treats a forced kill of the service's own
#    process as a crash, not a deliberate stop, and relaunches it
#    (~10s later) -- confirmed live: force-killing the service's
#    process by hand produced Event ID 7031 ("service terminated
#    unexpectedly ... Restart the service") and a fresh process tree.
#    The force-kill fallback below is exactly the situation most likely
#    to hit this (it only fires when the graceful stop didn't finish in
#    time), so it now unregisters the service FIRST -- removing the
#    onfailure policy along with the registration -- before killing
#    anything SCM might still be watching. This is also now the ONLY
#    place that unregisters the service: netlanvas.iss's [UninstallRun]
#    used to also run `netlanvas-service.exe uninstall` as a separate,
#    unconditional second step after this script. Confirmed live: a
#    second uninstall attempt run back-to-back with a first one hit
#    that second step with nothing registered (this script had already
#    found none and skipped everything), and the service came back
#    running with a fresh process tree immediately afterward --
#    suspected (WinSW's own CLI isn't in this repo, so not fully
#    confirmed from source) to be WinSW's "uninstall" verb falling
#    through to its default "run as a service" behavior when the
#    target doesn't exist. Removing that second call (rather than just
#    guarding it) means there's exactly one place that owns "is this
#    service currently registered", which is what this script already
#    checks before doing anything else below.

$ErrorActionPreference = 'SilentlyContinue'

$serviceExe = Join-Path $PSScriptRoot 'netlanvas-service.exe'
$procNames = 'netlanvas', 'netlanvas-service', 'netlanvas_snmp_helper', 'netlanvas_ping_sweep'

if ((Get-Service -Name NetLanvas) -and (Test-Path $serviceExe)) {
    # Bounded graceful stop -- see NATIVE-19 point 1 above. Runs as a job
    # so a wedged app shutdown can't block the rest of this script; the
    # poll+force-kill below remains the real safety net either way.
    $stopJob = Start-Job -ScriptBlock { param($exe) & $exe stop | Out-Null } -ArgumentList $serviceExe
    Wait-Job -Job $stopJob -Timeout 20 | Out-Null
    Remove-Job -Job $stopJob -Force
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
while ((Get-Process -Name $procNames) -and $sw.Elapsed.TotalSeconds -lt 30) {
    Start-Sleep -Milliseconds 500
}

# Unregister BEFORE force-killing -- see NATIVE-19 point 2 above. This
# runs whether or not anything is still alive at this point: an
# uninstall needs the service gone either way, and doing it here
# (guarded on Get-Service, same as the stop above) makes this script
# the single owner of that step instead of netlanvas.iss also doing it
# separately and unconditionally.
if (Get-Service -Name NetLanvas -ErrorAction SilentlyContinue) {
    if (Test-Path $serviceExe) {
        & $serviceExe uninstall | Out-Null
    } else {
        & sc.exe delete NetLanvas | Out-Null
    }
}

Get-Process -Name $procNames | Stop-Process -Force
