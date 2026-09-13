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

say() { printf '  %s\n' "$*"; }

# Arguments are parsed before the root check, so --help works without sudo.
PURGE=false
ASSUME_YES=false
for arg in "$@"; do
    case "$arg" in
        --purge-data) PURGE=true ;;
        --yes|-y) ASSUME_YES=true ;;
        -h|--help)
            cat <<USAGE
Usage: sudo Tools/uninstall.sh [--purge-data] [--yes]

  --purge-data   also delete the captured logs and packet data
  --yes          do not prompt (for scripts; only deletes with --purge-data)

Without --purge-data the captured data is left in place. Deleting a month of
records is not something to do as a side effect of removing software.
USAGE
            exit 0 ;;
        *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

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

# Per-user preferences. Small, but they live in every account that ever opened
# the app, so leaving them means the software is not really gone -- and a
# reinstall would silently inherit stale display settings.
for HOME_DIR in /Users/*; do
    [ -d "$HOME_DIR" ] || continue
    USER_NAME=$(basename "$HOME_DIR")
    REMOVED=false
    for LEFTOVER in \
        "$HOME_DIR/Library/Preferences/${APP_ID}.plist" \
        "$HOME_DIR/Library/Caches/${APP_ID}" \
        "$HOME_DIR/Library/Saved Application State/${APP_ID}.savedState" \
        "$HOME_DIR/Library/HTTPStorages/${APP_ID}" \
        "$HOME_DIR/Library/WebKit/${APP_ID}"
    do
        if [ -e "$LEFTOVER" ]; then rm -rf "$LEFTOVER"; REMOVED=true; fi
    done
    # cfprefsd holds preferences in memory and rewrites the file on exit unless
    # it is told to forget them, so deleting the plist alone is not enough.
    if [ "$REMOVED" = true ]; then
        sudo -u "$USER_NAME" defaults delete "$APP_ID" 2>/dev/null || true
        say "preferences for $USER_NAME"
    fi
done

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
        CONFIRMED=false
        if [ "$ASSUME_YES" = true ]; then
            CONFIRMED=true
        elif [ -e /dev/tty ]; then
            printf "Delete it permanently? [y/N] "
            read -r REPLY </dev/tty 2>/dev/null || REPLY=""
            case "$REPLY" in [yY]*) CONFIRMED=true ;; esac
        else
            # Nowhere to ask. Keeping the data is the safe default; a script
            # that meant to delete it can pass --yes.
            say "no terminal to confirm on; keeping the data (pass --yes to delete)"
        fi

        if [ "$CONFIRMED" = true ]; then
            rm -rf "$DATA_ROOT"
            say "deleted $SIZE"
        else
            say "kept at $DATA_ROOT"
        fi
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
if [ -d "$DATA_ROOT" ]; then
    echo "Uninstalled. Captured data kept at:"
    echo "  $DATA_ROOT"
else
    echo "Uninstalled. Nothing left behind."
fi

# Name whatever is still on disk rather than assuming. A tool that reports
# success while leaving files around is why people distrust uninstallers.
LEFT=""
for TARGET in "$PLIST" "$LIBEXEC/nmcapd" "$APP" "$LOG_DIR"; do
    [ -e "$TARGET" ] && LEFT="$LEFT
  $TARGET"
done
if [ -n "$LEFT" ]; then
    echo
    echo "Still present, remove by hand:$LEFT"
fi
