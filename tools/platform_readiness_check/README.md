# NetLanvas Windows/Mac Platform Readiness Check

Standalone diagnostic tool. Proves (or disproves) whether the mechanism a
real Windows/Mac port would depend on — a containerized poller reaching
back out to its own host via SSH to run real, native networking commands
— actually works on your machine, **before** any time gets spent
refactoring the real NetLanvas codebase to use it. See `PUNCH_LIST.md`
(the versioned copy in Google Drive, `netlanvas-punchlist-v10.md` or
later — not anything in this git repo) for the full design this
validates, items WIN-1 through WIN-5.

This tool never touches the real NetLanvas application or its data. It's
safe to run, throw away, and re-run as many times as needed.

## What it checks

1. **Platform detection** — confirms (and explains) that the container
   itself can never know it's really running on Windows/Mac, then checks
   whatever signals are available (`host.docker.internal` resolution, an
   optional explicit override).
2. **This image's own tooling** — sanity check only.
3. **SSH reachability and authentication** to your real host.
4. **Real command execution on your real host** — gateway lookup,
   ARP/neighbor table, and whether `fping`/`nmap`/`snmpget`/`snmpwalk` are
   installed. **You** need to eyeball the gateway/ARP output and confirm
   it looks like your actual home/office network, not something that
   looks like a Docker-internal address — the script can run the
   command, but only you know what your real LAN looks like.
5. **Where the SSH connection actually came from** — reads
   `SSH_CONNECTION` on the host itself to show the real source address
   this container's SSH session arrived from, and which local interface
   accepted it. This is what tells you whether `sshd` can safely be
   scoped down to `ListenAddress 127.0.0.1` (no LAN exposure at all) or
   needs to allow a real subnet instead — see "Turn SSH off" below for
   why this matters.
6. **Subnet-wide reachability sweep** — the first stage that goes beyond
   "does the mechanism work" into "will the real functions work."
   Deliberately agnostic: derives the subnet from Stage 4's own gateway
   finding (assumes a `/24`, override with
   `READINESS_SUBNET_CIDR_SUFFIX`) rather than assuming anything about
   what's on your network, then sweeps it with `fping` (preferred) or
   `nmap -sn` (fallback). Skips cleanly with a `WARN` if neither tool is
   present — an expected, useful finding on its own (see WIN-4).
7. **SNMP reachability probe** — takes whatever Stage 6 found alive
   (capped at 15 by default, `READINESS_SNMP_PROBE_LIMIT` to change),
   and tries `snmpget` with the `public` community against each,
   exercising the actual SNMP path end-to-end rather than just checking
   the binary exists. Any real replies are genuine findings, not test
   noise.
8. **nmap smoke test** — a single fast scan of just the gateway (not a
   full subnet port scan), only runs if Stage 6 used `fping` instead of
   `nmap` for the sweep (so nmap itself hasn't been exercised yet).
9. **Bundled SNMP helper (Windows-only, WIN-9 proof of concept)** —
   only runs if `snmpget` wasn't found in Stage 4. Pushes a small
   pre-built helper (`snmp_helper/`, a thin Go wrapper around
   [gosnmp](https://github.com/gosnmp/gosnmp), cross-compiled into this
   image at build time — see the Dockerfile's `snmp-helper-builder`
   stage) to the host over the same SSH connection via SFTP, runs a
   real SNMP GET with it, then deletes it again. Nothing is downloaded
   from anywhere else at runtime — the binary is built fresh from
   source every image build. A `PASS` here is live proof the WIN-9 gap
   has a real, working fix, not just a proposal. Functionally verified
   locally (real SNMP reply from a real device, clean timeout handling
   on a non-responding one, and the full SFTP-push/exec/cleanup flow
   tested against a throwaway local sshd) before ever being tested
   against a real Windows machine.
10. **SSH exposure lock-down (Windows-only, opt-in)** — doesn't run
    unless `READINESS_APPLY_LOCKDOWN=1` is set, since this is the one
    stage that changes real security configuration rather than just
    reading from the host. Applies a Windows Firewall rule restricting
    `sshd` to `RemoteAddress 127.0.0.1` over the already-open
    connection, then opens a genuinely **new** connection to test
    whether the restriction blocks fresh SSH sessions (the original
    connection proves nothing on its own — firewall changes don't drop
    connections already established). If the new connection fails, it
    automatically rolls back using the still-open original connection.
    See "Locking SSH down" below for why this exists instead of the
    simpler-looking `ListenAddress` approach.

## Locking SSH down when you're done

**Correction, found live:** an earlier version of this tool suggested
binding `sshd`'s own `ListenAddress` to `127.0.0.1` as "recommended,"
based on Stage 5 showing the connection's source as loopback. On real
Windows hardware, that broke SSH access entirely. Docker Desktop's
internal proxy doesn't arrive via the literal loopback *interface* at
the socket-bind level, even though the packet's *source address*
genuinely is `127.0.0.1` by the time `sshd` sees it — confirmed via
`SSH_CONNECTION`, which reads the real socket peer address, not
something cosmetic. `ListenAddress` restricts by interface; filtering
by source address at the firewall layer respects the distinction that
actually matters here instead.

**Windows** — built into the tool as Stage 10 above rather than left as
another untested suggestion:
```
$env:READINESS_APPLY_LOCKDOWN = "1"
docker compose run --rm readiness-check
```
Read Stage 10's result: a `PASS` on "Fresh SSH connection succeeded
with the restriction in place" means it's safe and already applied. A
rollback message means it wasn't safe and was automatically undone —
back to normal.

**Mac** — deliberately **not** labeled recommended here, since it's
untested on real Mac hardware following the same reasoning that turned
out wrong on Windows:
```
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.netlanvas-backup
echo "ListenAddress 127.0.0.1" | sudo tee -a /etc/ssh/sshd_config
sudo launchctl kickstart -k system/com.openssh.sshd
```
Verify (`sudo lsof -iTCP:22 -sTCP:LISTEN`), then genuinely re-run the
test rather than assuming it's fine. If Stage 3 breaks the same way it
did on Windows, revert (`sudo cp
/etc/ssh/sshd_config.netlanvas-backup /etc/ssh/sshd_config &&
sudo launchctl kickstart -k system/com.openssh.sshd`) and fall back to
a source-address-filtering approach on macOS's `pf` firewall instead —
analogous to the Windows Firewall fix above, deliberately not published
here as a default until it's actually been tested against real
hardware.

## Turn SSH off when you're done

If you'd rather not leave anything listening at all between uses, this
is simpler than the loopback lock above.

Enabling Remote Login (Mac) or the OpenSSH Server (Windows) opens that
port to brute-force attempts from anything that can route to it, and
this test doesn't need it left on between runs. Two things worth doing:

- **Turn the service back off** once you've read the report — System
  Settings → Sharing → Remote Login off (Mac). On Windows, to match how
  it was installed (the MSI method below), fully remove it rather than
  just stopping it. This also removes the service registration and
  firewall rule if setup had to create those by hand (harmless if it
  didn't — the commands just find nothing to remove). Doesn't touch
  Docker Desktop or WSL2 — those stay installed:
  ```
  Stop-Service sshd -ErrorAction SilentlyContinue
  sc.exe delete sshd
  Remove-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue
  Get-Package -Name "*OpenSSH*" -ErrorAction SilentlyContinue | Uninstall-Package -Force
  ```
  (If you installed it the older way, via `Add-WindowsCapability`,
  remove it the same way instead:
  `Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`.)
  Or, if you expect to re-run this test again soon, just stop it
  without uninstalling: `Stop-Service sshd` +
  `Set-Service -Name sshd -StartupType Manual`.
- **If Stage 5 above showed the connection arrived from `127.0.0.1`**,
  consider scoping `sshd` to loopback-only instead of turning it off
  entirely — add `ListenAddress 127.0.0.1` to `sshd_config`
  (`/etc/ssh/sshd_config` on Mac, `C:\ProgramData\ssh\sshd_config` on
  Windows) and restart the service. This removes LAN exposure while
  still letting this mechanism (and a real future NetLanvas install)
  work, since the container's connection never actually needs to leave
  the host. If Stage 5 showed a real (non-loopback) source address
  instead, loopback-only would break it — leave it open only for as
  long as you're actively testing.
- **Also remove the test key from `authorized_keys`.** It stays a valid
  login credential even after the SSH service is off. From this
  directory (the Windows version checks both possible locations setup
  could have written to — regular account vs. administrator account —
  whichever wasn't used simply has nothing to remove):
  ```
  # Mac
  grep -vFf netlanvas_readiness_key.pub ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp \
    && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys
  rm netlanvas_readiness_key netlanvas_readiness_key.pub

  # Windows (PowerShell)
  $key = Get-Content .\netlanvas_readiness_key.pub
  if (Test-Path $env:USERPROFILE\.ssh\authorized_keys) {
      (Get-Content $env:USERPROFILE\.ssh\authorized_keys) | Where-Object { $_ -ne $key } | Set-Content $env:USERPROFILE\.ssh\authorized_keys
  }
  if (Test-Path C:\ProgramData\ssh\administrators_authorized_keys) {
      (Get-Content C:\ProgramData\ssh\administrators_authorized_keys) | Where-Object { $_ -ne $key } | Set-Content C:\ProgramData\ssh\administrators_authorized_keys
  }
  Remove-Item netlanvas_readiness_key, netlanvas_readiness_key.pub
  ```
- **Also remove the built container image and network.** `docker
  compose run --rm` already removed the container itself when it
  finished; this cleans up what's left (same command on both
  platforms, from this directory):
  ```
  docker compose down --rmi local
  ```
  Optionally, delete the whole directory afterward — nothing in it is
  needed again unless you re-run the test.

## One-time setup

### Networking tools (Stages 6-8 need these on the real host, not just in the container)

**macOS** — installs Homebrew first only if you don't already have it, then all three tools:
```
command -v brew >/dev/null || /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install fping nmap net-snmp
brew link --force net-snmp
```
That last line matters — Homebrew's `net-snmp` is keg-only (macOS ships its
own different, older SNMP tools, so Homebrew won't overwrite them by
default), meaning `snmpget`/`snmpwalk` won't be on `PATH` without it.
`brew doctor` may warn about the forced link afterward — safe to ignore,
it's the documented way to use this formula.

**Windows** — only nmap has a clean install path:
```
winget install --id Insecure.Nmap -e
```
**Known gap, confirmed via research, not an oversight**: unlike Mac,
Windows has no clean install path for `fping` or
`snmpget`/`snmpwalk` — no winget package for either, no Chocolatey
package providing the actual SNMP CLI tools (only a GUI MIB browser),
and the Net-SNMP project itself only distributes source code for
Windows, no official binary. Deliberately not pointing at an unverified
third-party binary for a security-adjacent tool here — this is a real
finding logged as WIN-9 in the punch list; the real Windows port will
need its own answer (bundled binaries, or a different SNMP
implementation just for that platform). `fping`'s absence doesn't cost
the subnet sweep, though — Stage 6 automatically falls back to `nmap
-sn`. SNMP specifically will show `WARN — Skipped` on Windows for now;
that's the correct, expected result, not a bug.

### macOS

1. Enable Remote Login: **System Settings → General → Sharing → Remote
   Login** → On. (Or: `sudo systemsetup -setremotelogin on` in Terminal
   — this will prompt for your password, same as the GUI toggle.)
2. In Terminal, in this directory:
   ```
   ssh-keygen -t ed25519 -f ./netlanvas_readiness_key -N ""
   cat ./netlanvas_readiness_key.pub >> ~/.ssh/authorized_keys
   ```
3. Note your macOS username (`whoami`) — you'll need it below.

### Windows

0. **Before installing Docker Desktop**, check virtualization + WSL2 —
   Docker's own "Virtualization support not detected" error doesn't
   distinguish a BIOS-level problem from Windows' WSL2 feature simply
   being off (confirmed live, it shows identically for both), so check
   properly instead of guessing. In an **Administrator** PowerShell:
   ```
   $hv = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
   if ($hv) {
       Write-Host "Virtualization: already active. Nothing to do -- install Docker Desktop." -ForegroundColor Green
   } else {
       wsl --install
       Write-Host "If that failed with a virtualization-related error, VT-x/AMD-V may genuinely be off in" -ForegroundColor Yellow
       Write-Host "your PC's BIOS/UEFI firmware. Otherwise, restart your PC now, then install Docker Desktop." -ForegroundColor Yellow
   }
   ```
   `wsl --install` handles everything WSL2 needs in one step. Confirmed
   live: running just `dism.exe /online /enable-feature` for
   `Microsoft-Windows-Subsystem-Linux` and `VirtualMachinePlatform` on
   their own isn't enough — `wsl --status` still reported WSL as not
   installed afterward. Restart is required either way, then install
   Docker Desktop and wait for it to say "running".

   This deliberately checks `HypervisorPresent` rather than the more
   commonly-suggested `Get-ComputerInfo -Property
   "HyperVRequirementVirtualizationFirmwareEnabled"`. Confirmed live on
   a machine with Docker/WSL2 already working perfectly: that property
   falsely reported virtualization as OFF — a known, currently-open
   [Microsoft/WSL bug](https://github.com/microsoft/wsl/issues/14384),
   not a real BIOS problem. `HypervisorPresent` is the reliable
   ground-truth check instead.
1. Enable OpenSSH Server. Install Microsoft's official MSI directly
   (confirmed more reliable than the Windows-Update-based
   `Add-WindowsCapability` route, which can hang indefinitely or fail
   outright on some networks/managed PCs), then verify it actually
   worked — confirmed live, the MSI can report success while silently
   failing to register the Windows service — and complete it by hand if
   not. In an **Administrator** PowerShell:
   ```
   $release = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases/latest"
   $asset = $release.assets | Where-Object { $_.name -like "OpenSSH-Win64-v*.msi" }
   Invoke-WebRequest -Uri $asset.browser_download_url -OutFile "$env:TEMP\OpenSSH.msi"
   Start-Process msiexec.exe -ArgumentList "/i `"$env:TEMP\OpenSSH.msi`" /quiet /norestart" -Wait

   if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
       Write-Host "MSI didn't register the sshd service -- completing it by hand." -ForegroundColor Yellow
       & "C:\Program Files\OpenSSH\ssh-keygen.exe" -A
       New-Service -Name sshd -BinaryPathName '"C:\Program Files\OpenSSH\sshd.exe"' -DisplayName "OpenSSH SSH Server" -StartupType Automatic
       New-NetFirewallRule -Name sshd -DisplayName "OpenSSH SSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
   }

   Start-Service sshd
   Set-Service -Name sshd -StartupType Automatic
   ```
   (If `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`
   already worked for you, that's fine too — no need to redo it.)
2. In a regular PowerShell, in this directory. Windows OpenSSH ignores
   the normal per-user `authorized_keys` for accounts in the local
   Administrators group — confirmed live, it only reads
   `administrators_authorized_keys` instead, with restricted
   permissions required — so this checks which kind of account you're
   using and writes to the right place:
   ```
   ssh-keygen -t ed25519 -f .\netlanvas_readiness_key -N '""'
   $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   if ($isAdmin) {
       if (!(Test-Path C:\ProgramData\ssh)) { mkdir C:\ProgramData\ssh }
       Get-Content .\netlanvas_readiness_key.pub | Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys
       icacls.exe "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r
       icacls.exe "C:\ProgramData\ssh\administrators_authorized_keys" /grant "Administrators:F" "SYSTEM:F"
   } else {
       if (!(Test-Path $env:USERPROFILE\.ssh)) { mkdir $env:USERPROFILE\.ssh }
       Get-Content .\netlanvas_readiness_key.pub | Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys
   }
   ```
3. Note your Windows username (`echo $env:USERNAME`) — you'll need it
   below.

### Linux (for comparison / sanity-checking the tool itself)

Not the point of this tool (Linux already works today via
`network_mode: host`), but it'll run there too if you want to see what a
"native, no SSH relay needed" baseline looks like. Same steps as macOS.

## Running it

```
docker compose build
READINESS_SSH_USER=<your-username> docker compose run --rm readiness-check
```

Add `READINESS_VERBOSE=1` in front of that for more detailed logging if
something's unclear. If `NETLANVAS_HOST_OS` inference in Stage 1 looks
wrong, you can force it: `NETLANVAS_HOST_OS=windows docker compose run ...`
(this doesn't change what the tool does, only what it prints — Stage 1 is
purely informational here, not a real port).

## Reading the results

- **All green through Stage 4, and the gateway/ARP output looks like
  your real network** → the mechanism is validated, worth investing in
  the real refactor (WIN-3 in the punch list).
- **Stage 3 fails** → SSH isn't reachable/working yet. Re-check the
  one-time setup steps above, especially that the service is actually
  running (`Get-Service sshd` on Windows, or check System Settings on
  Mac).
- **Stage 3 passes but Stage 4's gateway output looks like a Docker
  address, not your real router** → this would be a genuinely important,
  surprising finding — save the full output and flag it, since it would
  mean the core assumption behind the whole design needs rethinking.
- **Stage 6/7/8 show `WARN — Skipped` for a missing tool** → expected
  and useful, not a failure — it's telling you fping/nmap/snmpget
  aren't installed on this host yet (WIN-4), which the real install
  script needs to handle automatically.
- **Stage 6 finds an implausible number of hosts** (zero on a network
  you know has devices, or way more than expected) → worth flagging;
  could mean the `/24` subnet-size assumption is wrong for this network
  (set `READINESS_SUBNET_CIDR_SUFFIX`), or that fping/nmap's output
  format differs from what this script expects on that platform.

## Debugging

Everything logs to stdout — `docker compose run --rm readiness-check`
already shows it all. For more detail, prefix with `READINESS_VERBOSE=1`.

## Troubleshooting

**"Is a directory" error, or the SSH key check fails even though you
generated one** — Docker will silently create an empty *directory* at
`./netlanvas_readiness_key` if you run `docker compose run` before the
key file actually exists there (confirmed hitting this during testing).
If that happens: `rm -rf netlanvas_readiness_key netlanvas_readiness_key.pub`
and regenerate the key before running the tool again.
