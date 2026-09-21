; NetLanvas Windows installer
;
; NATIVE-4 (Phase 3, installer): installs as a real Windows Service
; (LocalSystem, starts at boot regardless of login state) via WinSW
; (github.com/winsw/winsw, MIT-licensed) wrapping the plain console
; netlanvas.exe -- the app itself has no service-control-handler code,
; WinSW handles process lifecycle/start/stop externally, the standard
; way to run an existing console app as a service without modifying it.
;
; Static program files go in {app} (Program Files); mutable data
; (network.db, config.db, TLS/identity material, service logs) goes in
; C:\ProgramData\NetLanvas -- standard Windows convention (Program
; Files is for the program, ProgramData is for what it produces),
; also survives an upgrade/reinstall since it's outside {app}.
;
; NATIVE-13: always serves real (self-signed) TLS now, localhost-only
; by default with an opt-in "Enable Remote Web Viewing" Settings-page
; toggle for LAN access -- see main.py's NATIVE branch. The firewall
; rule below is pre-created but DISABLED at install time, matching
; that off-by-default posture; the app flips it on/off itself as the
; Settings toggle changes (main.py's _sync_windows_firewall_rule()).

#define MyAppName "NetLanvas"
#define MyAppVersion "3.20.0"
#define MyAppPublisher "NetLanvas"
#define MyAppURL "https://netlanvas.com"
#define MyDataDir "C:\ProgramData\NetLanvas"

[Setup]
AppId={{B7E1C2A4-6F3D-4A8B-9C1E-3D5F7A9B2C4E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
; netlanvas.exe is a genuine x64 PyInstaller build -- without this,
; Inno Setup defaults to 32-bit mode and {autopf} resolves to
; "Program Files (x86)" even on a 64-bit OS, which is the wrong
; location for a 64-bit binary (confirmed live: this happened on the
; first build of this installer before the directive was added).
ArchitecturesInstallIn64BitMode=x64compatible
DefaultDirName={autopf}\NetLanvas
DefaultGroupName=NetLanvas
DisableProgramGroupPage=yes
; A Windows Service needs to be installed/registered under an elevated
; account -- this triggers the UAC prompt during setup.
PrivilegesRequired=admin
OutputBaseFilename=NetLanvas-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\netlanvas.exe
; NATIVE-17 (2026-09-04): Inno Setup's own built-in Restart Manager
; integration (CloseApplications, on by default as of 6.7.x) runs
; BEFORE PrepareToInstall does, tries to auto-close whatever's holding
; netlanvas.exe (a console-mode Windows Service process, which has no
; window for RM to politely ask to close), fails within about a
; second, and -- since message boxes are suppressed in the [Run]-time
; unattended path -- silently rolls back the entire install rather
; than proceeding. Confirmed live: this bypassed PrepareToInstall's
; own stop-and-wait fix entirely on the first test, a different
; failure mode from the original DeleteFile error. Disabling it here
; hands the whole "make sure nothing's holding our files" job to
; PrepareToInstall's stop-netlanvas.ps1 (which actually knows this is
; a Windows Service, not a GUI app RM can message-box its way through)
; instead of racing two separate, uncoordinated mechanisms.
CloseApplications=no
RestartApplications=no

[Files]
Source: "build\netlanvas.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\netlanvas-service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\netlanvas-service.xml"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\stop-netlanvas.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\ui\*"; DestDir: "{app}\ui"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "build\tools\*"; DestDir: "{app}\tools"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; NATIVE-16: DisableProgramGroupPage only skips the wizard page that
; lets the user rename the Start Menu folder -- it does NOT create any
; icons on its own, and this file previously had no [Icons] section at
; all, so a fresh install left literally no discoverable way to
; uninstall NetLanvas short of knowing to open Windows Settings > Apps
; (unins000.exe in {app} works, but nothing pointed a user at it, or at
; this directory, at all). Confirmed live as real user-reported
; friction (2026-09-02, v3.8.4 first-run feedback on Marks-PC): "we
; need an uninstaller." Inno Setup's own uninstall entry in Apps &
; Features already existed the whole time (UninstallDisplayIcon above
; proves the metadata was always there) -- this is purely about making
; it findable, not about fixing a missing uninstall mechanism.
Name: "{group}\Uninstall NetLanvas"; Filename: "{uninstallexe}"

[Dirs]
; Created here (not left to the service's own first-run bootstrap) so
; the ACLs are right and the paths exist before WinSW ever starts the
; service -- LocalSystem has implicit full control under ProgramData,
; this is just making sure the tree exists up front.
Name: "{#MyDataDir}\data"
Name: "{#MyDataDir}\data\tls"
Name: "{#MyDataDir}\logs"

[Run]
; Installs and starts the service. Runs elevated (inherited from
; PrivilegesRequired=admin above) -- WinSW's "install" subcommand
; registers the service using netlanvas-service.xml's own <id>/
; <executable>/<env> configuration, "start" then launches it.
Filename: "{app}\netlanvas-service.exe"; Parameters: "install"; Flags: runhidden waituntilterminated
Filename: "{app}\netlanvas-service.exe"; Parameters: "start"; Flags: runhidden waituntilterminated
; NATIVE-16 follow-up: this pause used to live inside CurPageChanged on
; the Finished page itself (polling for welcome.txt with Sleep()) --
; Pascal Script's Sleep() blocks the whole wizard thread's message
; pump, so the Finished page's own transition (title, body text, and
; button all repainting together) stalled mid-way through, and
; whatever was on screen from the PREVIOUS page kept showing until the
; wait ended. Confirmed live as real user feedback (2026-09-02, v3.8.5
; first-run on Marks-PC): "the finish button appears before the
; 'completing the NetLanvas setup...' text" -- disabling the button
; (the previous attempt at this fix) didn't help, because a disabled
; control's changed appearance doesn't repaint during a Sleep() either.
; Waiting HERE instead -- on the installing/progress page, where a
; pause is already the expected, normal thing to see -- means the
; Finished page itself never blocks: by the time Inno transitions to
; it, the service has had several extra seconds to generate its TLS
; cert/device identity and write welcome.txt, so CurPageChanged's own
; (now instant, no-loop) read just works, and the whole page paints as
; one consistent unit like every other page does.
Filename: "{sys}\cmd.exe"; Parameters: "/c ping -n 8 127.0.0.1 >NUL"; Flags: runhidden waituntilterminated
; Pre-created disabled (enable=no) -- matches remote access being off
; by default; the app's own boot sequence enables/disables this same
; rule (by name) as the Settings-page toggle changes, never adds a
; second one. Created here rather than left entirely to the running
; service so the exception is visible/auditable as part of what the
; installer does to the system, not a background service silently
; opening a firewall port with no user-visible install-time action.
;
; BUG-25 (found 2026-09-15 alongside BUG-24): this comment's own claim
; above -- "never adds a second one" -- was wrong. An in-place upgrade
; (installing a new version over an existing install, no uninstall in
; between) re-runs this whole [Run] section every time, and `netsh
; add rule` has no upsert semantics -- it unconditionally creates a
; NEW rule even when one of the same name already exists. Confirmed
; live on Marks-PC: 3 real duplicate "NetLanvas Remote Web Viewing"
; rules after 3 in-place upgrades, 2 stuck enabled=true even after the
; Settings toggle was switched off -- `netsh set rule` does not
; reliably flip every same-named duplicate, so a stale enabled
; duplicate can leave the port reachable even when the app and the
; user both believe remote access is off. Deleting first makes this
; step idempotent the same way the [UninstallRun] delete below already
; is -- routed through cmd.exe with a forced `exit /b 0` because,
; unlike [UninstallRun]'s delete (which always has a real rule to
; remove, created by a prior install), THIS delete runs on a genuinely
; fresh install too, where no rule exists yet and plain `netsh delete`
; returns a nonzero "No rules match" exit code -- which Inno Setup's
; [Run] treats as a fatal setup error by default.
Filename: "{sys}\cmd.exe"; Parameters: "/c netsh advfirewall firewall delete rule name=""NetLanvas Remote Web Viewing"" >nul 2>&1 & exit /b 0"; Flags: runhidden waituntilterminated
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""NetLanvas Remote Web Viewing"" dir=in action=allow protocol=TCP localport=8899 enable=no"; Flags: runhidden waituntilterminated
; NATIVE-16: this used to carry the "postinstall" flag, which puts it
; on the Finished page as an unchecked-by-default... no, CHECKED but
; UNCHECKABLE-looking checkbox ("Open NetLanvas setup in your
; browser"). That's real UX only for a genuinely optional post-install
; action -- this one isn't: there is no other way to create the admin
; account and finish setup, so a user who unchecks it (or just doesn't
; notice a checkbox needs leaving checked) is left on a plain "Setup
; is complete" screen with no indication anything else is required.
; Confirmed live as real user feedback (2026-09-02, v3.8.4 first-run on
; Marks-PC): "the optional open browser to continue is not optional,
; so we shouldn't give a tick box." Dropping "postinstall" removes the
; checkbox entirely -- this now just always runs as a normal [Run]
; step (skipifsilent still skips it for unattended installs, where
; there's no interactive user present to complete setup anyway). The
; CurPageChanged code below replaces the checkbox's old explanatory
; role with static text on the Finished page instead.
Filename: "https://127.0.0.1:8899/dashboard/settings.html"; Flags: shellexec skipifsilent

[UninstallRun]
; Must stop and unregister the service BEFORE Inno Setup's automatic
; file removal deletes netlanvas.exe out from under a running process.
; NATIVE-17 (2026-09-04): stop-netlanvas.ps1 replaces a fixed
; "ping -n 4" pause that had been intermittently too short for 7+
; releases -- see the script's own header for the full story (WinSW's
; "stop" CLI reports success well before the real process tree has
; actually exited; this polls for genuine completion instead of
; guessing a duration, with a force-kill fallback).
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\stop-netlanvas.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "StopNetLanvasService"
Filename: "{app}\netlanvas-service.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "UninstallNetLanvasService"

; Remove the firewall exception this installer created -- an orphaned
; ALLOW rule surviving an uninstall is pure downside (nothing left
; running to legitimately use it) with no upside kept.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""NetLanvas Remote Web Viewing"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveNetLanvasFirewallRule"

; ProgramData (the network database, TLS/identity material, and logs)
; is deliberately left in place on uninstall -- same convention as
; every other Windows app that separates "the program" from "what it
; produced": uninstalling NetLanvas shouldn't silently destroy a
; user's collected network history. A future "remove all data too"
; checkbox is a reasonable enhancement, not done here.

[Code]
// NATIVE-17 (2026-09-04): stops any already-running NetLanvas service
// BEFORE [Files] copies anything, and waits for its real process tree
// to exit -- not just a fixed pause. Confirmed live: an in-place
// reinstall/upgrade over an already-installed NetLanvas hit
// "DeleteFile failed; code 5, Access is denied" on netlanvas.exe
// during [Files] copy. [UninstallRun]'s own stop step only ever fires
// when the OLD version's own uninstaller runs (Control Panel /
// unins000.exe) -- launching a NEW installer over an existing install
// with the same AppId never triggers it, so without this hook the
// previous install's service (and the netlanvas.exe/helper processes
// it spawned) would still be holding those files open. PrepareToInstall
// is Inno Setup's dedicated "runs after the user clicks Install, before
// any files are touched" callback -- the correct place for exactly
// this, not InitializeSetup (too early, before the wizard pages) or a
// [Run] step (too late, [Run] only executes after [Files] has already
// copied everything).
//
// Deliberately does NOT rely on {app}\stop-netlanvas.ps1 existing --
// confirmed live: an upgrade FROM a version that predates this fix
// (e.g. v3.10.2, which never shipped that file) silently skipped the
// whole stop-and-wait step on a FileExists check, hitting the exact
// same DeleteFile error this was meant to close. Writes the identical
// wait/kill logic to a fresh temp file every run instead, so it works
// unconditionally regardless of what the previous install shipped.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  ScriptPath: String;
  ScriptLines: TArrayOfString;
begin
  Result := '';
  SetArrayLength(ScriptLines, 5);
  ScriptLines[0] := '$ErrorActionPreference = ''SilentlyContinue''';
  ScriptLines[1] := 'if (Get-Service -Name NetLanvas) { & ''' + ExpandConstant('{app}') + '\netlanvas-service.exe'' stop | Out-Null }';
  ScriptLines[2] := '$procNames = ''netlanvas'', ''netlanvas-service'', ''netlanvas_snmp_helper'', ''netlanvas_ping_sweep''';
  ScriptLines[3] := '$sw = [System.Diagnostics.Stopwatch]::StartNew(); while ((Get-Process -Name $procNames) -and $sw.Elapsed.TotalSeconds -lt 30) { Start-Sleep -Milliseconds 500 }';
  ScriptLines[4] := 'Get-Process -Name $procNames | Stop-Process -Force';

  ScriptPath := ExpandConstant('{tmp}\netlanvas-stop-wait.ps1');
  if SaveStringsToFile(ScriptPath, ScriptLines, False) then
  begin
    Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' + ScriptPath + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

// NATIVE-16: surfaces the first-run setup card (TLS certificate
// fingerprint + one-time setup token + setup URL) directly on the
// Finished page, and explains the certificate warning the user is
// about to see in their browser -- confirmed live as real user
// feedback (2026-09-02, v3.8.4 first-run on Marks-PC): "Add a note
// that they should click advanced, proceed etc, and maybe display
// the certificate hash." The service (started by [Run] above) writes
// this exact card to welcome.txt within a few seconds of boot -- see
// security/welcome.py's write_welcome_file(), the same file
// get_setup_token() reads for the Settings page's own auto-fill.
// Reusing it here (rather than re-deriving the fingerprint/token
// separately in Pascal) guarantees the installer can never show a
// value that drifts from what the running app actually generated.
function ReadWelcomeCardText(): String;
var
  WelcomePath: String;
  Lines: TArrayOfString;
  Content: String;
  I: Integer;
begin
  WelcomePath := ExpandConstant('{#MyDataDir}\data\tls\welcome.txt');
  Result := '';
  // NATIVE-16 follow-up: deliberately NOT waiting/polling here anymore
  // -- this used to Sleep()-loop for up to ~5s, but that blocks the
  // wizard's message pump entirely, so the Finished page's own
  // transition (title, body, button) stalled mid-repaint until the
  // wait ended -- confirmed live as real user feedback (2026-09-02,
  // v3.8.5 first-run on Marks-PC): "the finish button appears before
  // the 'completing the NetLanvas setup...' text." The actual wait now
  // happens earlier, as a [Run] step on the installing/progress page
  // (see netlanvas.iss's own comment there) -- by the time
  // CurPageChanged below runs, welcome.txt should already exist, so
  // this can just check once. The generic fallback text below still
  // covers the rare case it somehow isn't ready yet.
  if FileExists(WelcomePath) then
  begin
    if LoadStringsFromFile(WelcomePath, Lines) then
    begin
      for I := 0 to GetArrayLength(Lines) - 1 do
      begin
        // Strip the BEGIN/END grep-markers -- meant for pulling this
        // card out of `docker logs` output, meaningless to a human
        // reading it directly on the Finished page.
        if (Pos('NETLANVAS-SETUP-CARD', Lines[I]) = 0) then
          Content := Content + Lines[I] + #13#10;
      end;
      Result := Content;
    end;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
var
  CardText: String;
begin
  if CurPageID = wpFinished then
  begin
    // No wait here anymore -- see ReadWelcomeCardText's own comment.
    // This now runs synchronously and instantly, so the page's title,
    // this label, and the Finish button all paint together in one
    // pass, the same as every other wizard page.
    CardText := ReadWelcomeCardText();
    WizardForm.FinishedLabel.WordWrap := True;
    WizardForm.FinishedLabel.AutoSize := True;
    if CardText <> '' then
    begin
      WizardForm.FinishedLabel.Caption :=
        'Setup is almost done. Your browser will now open automatically to finish it -- creating the admin account is the one step this installer can''t do for you.' + #13#10 + #13#10 +
        'Your browser will show a certificate warning first: NetLanvas uses a private certificate it generates for this device, not one from a public certificate authority, so this is expected. Click "Advanced", then "Proceed" (wording varies by browser) -- but verify the fingerprint below matches what your browser shows before you do:' + #13#10 +
        CardText;
    end
    else
    begin
      // Falls back to generic guidance if the card wasn't ready in
      // time (see ReadWelcomeCardText's own comment) -- the Settings
      // page itself still auto-fills the real token/fingerprint via
      // get_setup_token(), so setup isn't blocked, just less
      // pre-informed than usual for this one run.
      WizardForm.FinishedLabel.Caption :=
        WizardForm.FinishedLabel.Caption + #13#10 + #13#10 +
        'Setup is almost done. Your browser will now open automatically to finish it. It will show a certificate warning first -- NetLanvas uses a private certificate it generates for this device, so this is expected. Click "Advanced", then "Proceed" (wording varies by browser) to continue; the setup token is already filled in on the page that follows.';
    end;
  end;
end;
