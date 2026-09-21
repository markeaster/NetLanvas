#!/bin/bash
# NATIVE-16 (macOS uninstaller): a .pkg has no built-in uninstall entry
# the way an Inno Setup installer does, so this ships as its own
# double-clickable script (placed at /Applications/Uninstall
# NetLanvas.command by postinstall) -- addressing the exact
# discoverability gap real user feedback flagged on the Windows side
# ("we need an uninstaller") before it could recur here too.
#
# Data (network.db, config.db, TLS/identity material, logs) is
# deliberately left in place, same convention as the Windows
# installer's [UninstallRun] -- uninstalling shouldn't silently
# destroy a user's collected network history. Removal instructions are
# printed below for anyone who wants a genuinely clean slate.
set -e

echo "======================================================================"
echo " NetLanvas Uninstaller"
echo "======================================================================"
echo ""
echo "This will stop the NetLanvas service and remove it from this Mac."
echo "Your network database and settings will be left in place at:"
echo "  /Library/Application Support/NetLanvas/data"
echo ""
read -p "Continue? [y/N] " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo "Administrator password required to remove the system service:"
sudo launchctl bootout system /Library/LaunchDaemons/com.netlanvas.daemon.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.netlanvas.daemon.plist
sudo rm -rf "/Library/Application Support/NetLanvas/bin"
sudo pkgutil --forget com.netlanvas.pkg 2>/dev/null || true

echo ""
echo "NetLanvas has been uninstalled."
echo "Your data was kept at /Library/Application Support/NetLanvas/data --"
echo "delete that folder manually (as an administrator) for a full clean slate:"
echo "  sudo rm -rf \"/Library/Application Support/NetLanvas\""
echo ""
rm -f "/Applications/Uninstall NetLanvas.command"
read -p "Press Enter to close this window..."
