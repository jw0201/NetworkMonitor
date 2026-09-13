#!/bin/bash
#
# uninstall.sh -- remove the monitoring service.
#
# Run:  sudo Tools/uninstall.sh [--purge-data]
#
# Captured data is NOT removed unless --purge-data is given, and even then it
# asks. A security tool that silently deletes a month of forensic records on
# uninstall has destroyed the thing someone may be uninstalling it to go and
# look at.
#
set -uo pipefail

DAEMON_ID="com.narusec.networkmonitor.nmcapd"
GROUP="_networkmonitor"
DATA_ROOT="/Library/Application Support/NetworkMonitor"
LIBEXEC="/usr/local/libexec"
PLIST="/Library/LaunchDaemons/${DAEMON_ID}.plist"
LOG_DIR="/var/log/networkmonitor"
RIGHT="com.narusec.networkmonitor.admin"
APP="/Applications/NetworkMonitor.app"

PURGE=false
[ "${1:-}" = "--purge-data" ] && PURGE=true

say() { printf '  %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }

echo "Stopping the service"
if launchctl print "system/$DAEMON_ID" >/dev/null 2>&1; then
    # bootout sends SIGTERM and waits, which is what lets the daemon checkpoint
    # its database and finalise open flows rather than losing them.
    launchctl bootout "system/$DAEMON_ID" 2>/dev/null
    for _ in $(seq 1 30); do
        launchctl print "system/$DAEMON_ID" >/dev/null 2>&1 || break
        sleep 0.5
    done
    say "stopped"
else
    say "was not running"
fi

echo
echo "Removing"
rm -f "$PLIST" && say "$PLIST"
rm -f "$LIBEXEC/nmcapd" && say "$LIBEXEC/nmcapd"
[ -d "$APP" ] && rm -rf "$APP" && say "$APP"

if security authorizationdb read "$RIGHT" >/dev/null 2>&1; then
    security authorizationdb remove "$RIGHT" >/dev/null 2>&1 && say "authorization right"
fi

rm -f "$DATA_ROOT/peers.plist" && say "peer pinning"

if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    dseditgroup -o delete -q "$GROUP" 2>/dev/null && say "$GROUP group"
fi

rm -rf "$LOG_DIR"

# --- data -----------------------------------------------------------------

echo
if [ -d "$DATA_ROOT/db" ]; then
    SIZE=$(du -sh "$DATA_ROOT" 2>/dev/null | cut -f1)
    DAYS=$(ls "$DATA_ROOT/db/archive" 2>/dev/null | grep -c '\.db$' || echo 0)

    if [ "$PURGE" = true ]; then
        echo "Captured data: $SIZE across $DAYS archived day(s) plus today."
        printf "Delete it permanently? [y/N] "
        read -r REPLY </dev/tty
        case "$REPLY" in
            [yY]*) rm -rf "$DATA_ROOT"; say "deleted" ;;
            *) say "kept at $DATA_ROOT" ;;
        esac
    else
        cat <<EOF
Captured data kept: $SIZE across $DAYS archived day(s).

  $DATA_ROOT

It is no longer readable by the $GROUP group, which has been removed. To read
it later, reinstall; to delete it now:

  sudo Tools/uninstall.sh --purge-data
EOF
    fi
fi

echo
echo "Uninstalled."
