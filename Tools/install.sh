#!/bin/bash
#
# install.sh -- install the monitoring service.
#
# Run:  sudo Tools/install.sh [path/to/NetworkMonitor.app]
#
# What this does and why, in the order it matters:
#
#   * The daemon binary goes to /usr/local/libexec, NOT inside the .app.
#     /Applications is root:admin 0775 -- group-writable by non-root -- and
#     launchd refuses to run a daemon whose binary or plist can be written by
#     anyone but root. The resulting error is genuinely painful to diagnose.
#
#   * A _networkmonitor group is created and the installing admin added. The
#     databases hold every user's browsing metadata, so they are group-readable
#     and world-nothing. Members can read the logs directly, which is the fast
#     path; everyone else goes through the service.
#
#   * Both cdhashes are computed after signing and written to peers.plist.
#     Neither binary can contain the other's -- each would change the other's --
#     so the pinning is resolved out of band, here.
#
#   * A custom authorization right is installed. Changing what is collected is
#     then decided by authd rather than by either of our binaries.
#
set -euo pipefail

APP_ID="com.narusec.NetworkMonitor"
DAEMON_ID="com.narusec.networkmonitor.nmcapd"
GROUP="_networkmonitor"
DATA_ROOT="/Library/Application Support/NetworkMonitor"
LIBEXEC="/usr/local/libexec"
PLIST="/Library/LaunchDaemons/${DAEMON_ID}.plist"
LOG_DIR="/var/log/networkmonitor"
RIGHT="com.narusec.networkmonitor.admin"

cd "$(dirname "$0")/.."
BUNDLE="${1:-build/NetworkMonitor.app}"

say() { printf '  %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- preflight ------------------------------------------------------------

echo "Preflight"
[ "$(id -u)" -eq 0 ] || fail "must run as root: sudo Tools/install.sh"

MACOS_MAJOR=$(sw_vers -productVersion | cut -d. -f1)
[ "$MACOS_MAJOR" -ge 14 ] || fail "macOS 14 or later required (found $(sw_vers -productVersion))"

[ -d "$BUNDLE" ] || fail "no app bundle at $BUNDLE -- run Tools/bundle.sh first"
[ -x "$BUNDLE/Contents/Helpers/nmcapd" ] || fail "$BUNDLE has no Helpers/nmcapd"

# A bundle on a network or removable volume would leave launchd pointing at a
# path that may vanish.
case "$(df "$BUNDLE" | tail -1 | awk '{print $1}')" in
    /dev/*) ;;
    *) fail "the bundle must be on a local volume" ;;
esac

codesign --verify --strict "$BUNDLE" 2>/dev/null \
    || fail "the app bundle is not validly signed -- run Tools/bundle.sh"
say "app bundle verified"

INSTALLING_USER="${SUDO_USER:-}"
[ -n "$INSTALLING_USER" ] || say "warning: no SUDO_USER; skipping group membership"

# --- readers group --------------------------------------------------------

echo
echo "Readers group"
if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    say "$GROUP already exists"
else
    dseditgroup -o create -q -r "NetworkMonitor readers" "$GROUP"
    say "created $GROUP"
fi

if [ -n "$INSTALLING_USER" ]; then
    if dseditgroup -o checkmember -m "$INSTALLING_USER" "$GROUP" >/dev/null 2>&1; then
        say "$INSTALLING_USER is already a member"
    else
        dseditgroup -o edit -a "$INSTALLING_USER" -t user "$GROUP"
        say "added $INSTALLING_USER"
    fi
fi

# --- data directories -----------------------------------------------------

echo
echo "Data directories"
mkdir -p "$DATA_ROOT" "$DATA_ROOT/db" "$DATA_ROOT/db/archive" \
         "$DATA_ROOT/pcap" "$DATA_ROOT/export" "$LOG_DIR"

chown root:wheel "$DATA_ROOT"
chmod 0755 "$DATA_ROOT"

# 0770, not 0750. A read-only SQLite connection to a WAL database needs WRITE
# access to the -shm file, and when the daemon is not running the reader has to
# CREATE it -- which needs write permission on the directory. With 0750 that
# fails only when the daemon is down, which is the worst possible time for a
# confusing error.
chown -R "root:$GROUP" "$DATA_ROOT/db" "$DATA_ROOT/pcap" "$DATA_ROOT/export"
chmod 0770 "$DATA_ROOT/db" "$DATA_ROOT/export"
chmod 0750 "$DATA_ROOT/pcap" "$DATA_ROOT/db/archive"
chown root:wheel "$LOG_DIR"
chmod 0750 "$LOG_DIR"
say "$DATA_ROOT (db 0770 root:$GROUP)"

# --- binaries -------------------------------------------------------------

echo
echo "Binaries"
mkdir -p "$LIBEXEC"
install -o root -g wheel -m 0755 "$BUNDLE/Contents/Helpers/nmcapd" "$LIBEXEC/nmcapd"
say "$LIBEXEC/nmcapd"

INSTALLED_APP="/Applications/NetworkMonitor.app"
if [ "$(cd "$BUNDLE" && pwd)" != "$INSTALLED_APP" ]; then
    rm -rf "$INSTALLED_APP"
    cp -R "$BUNDLE" "$INSTALLED_APP"
    chown -R root:admin "$INSTALLED_APP"
    say "$INSTALLED_APP"
fi

# --- peer pinning ---------------------------------------------------------

echo
echo "Peer pinning"
APP_HASH=$(codesign -d --verbose=4 "$INSTALLED_APP" 2>&1 | awk -F'=' '/^CDHash/{print $2}')
DAEMON_HASH=$(codesign -d --verbose=4 "$LIBEXEC/nmcapd" 2>&1 | awk -F'=' '/^CDHash/{print $2}')

if [ -n "$APP_HASH" ] && [ -n "$DAEMON_HASH" ]; then
    cat > "$DATA_ROOT/peers.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>appIdentifier</key>    <string>$APP_ID</string>
    <key>appCDHash</key>        <string>$APP_HASH</string>
    <key>daemonIdentifier</key> <string>$DAEMON_ID</string>
    <key>daemonCDHash</key>     <string>$DAEMON_HASH</string>
</dict>
</plist>
PLIST
    chown root:wheel "$DATA_ROOT/peers.plist"
    chmod 0644 "$DATA_ROOT/peers.plist"
    say "app    $APP_HASH"
    say "daemon $DAEMON_HASH"
else
    say "warning: could not read cdhashes; peer checks will fall back to group membership"
fi

# --- authorization right --------------------------------------------------

echo
echo "Authorization"
if security authorizationdb read "$RIGHT" >/dev/null 2>&1; then
    say "$RIGHT already registered"
else
    # authenticate-admin: authd prompts for an administrator and decides.
    # Neither of our binaries gets to make that call.
    echo '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>class</key><string>user</string>
  <key>group</key><string>admin</string>
  <key>shared</key><false/>
  <key>timeout</key><integer>300</integer>
  <key>comment</key><string>Change what NetworkMonitor records and how long it keeps it.</string>
</dict></plist>' | security authorizationdb write "$RIGHT" >/dev/null
    say "registered $RIGHT"
fi

# --- launchd --------------------------------------------------------------

echo
echo "Service"
if launchctl print "system/$DAEMON_ID" >/dev/null 2>&1; then
    launchctl bootout "system/$DAEMON_ID" 2>/dev/null || true
    # bootout returns once launchd has accepted the request, not once the job
    # is gone, and this daemon takes real time to exit: it stops capture,
    # flushes pending rows, checkpoints the WAL and finalises open flows
    # (ExitTimeOut is 30). Bootstrapping a label that is still registered fails
    # with "Bootstrap failed: 5: Input/output error", which names neither the
    # cause nor the cure. uninstall.sh has always waited here; this did not.
    STOPPED=false
    for _ in $(seq 1 70); do
        launchctl print "system/$DAEMON_ID" >/dev/null 2>&1 || { STOPPED=true; break; }
        sleep 0.5
    done
    if [ "$STOPPED" = true ]; then
        say "stopped the previous instance"
    else
        fail "the previous instance is still registered after 35s.
  Stop it by hand and run this again:
    sudo launchctl bootout system/$DAEMON_ID"
    fi
fi

install -o root -g wheel -m 0644 \
    Tools/Resources/com.narusec.networkmonitor.nmcapd.plist "$PLIST"
plutil -lint "$PLIST" >/dev/null || fail "the LaunchDaemon plist is malformed"

# enable before bootstrap, not after: a label left disabled in launchd's
# override database is the other thing that makes bootstrap fail with EIO, and
# enabling it afterwards is too late to have helped.
launchctl enable "system/$DAEMON_ID" 2>/dev/null || true

if ! BOOTSTRAP_ERR=$(launchctl bootstrap system "$PLIST" 2>&1); then
    case "$BOOTSTRAP_ERR" in
        *"Input/output error"*)
            fail "launchd refused the job: $BOOTSTRAP_ERR
  This almost always means the label is still registered. Check and clear it:
    sudo launchctl print system/$DAEMON_ID
    sudo launchctl bootout system/$DAEMON_ID" ;;
        *)
            fail "launchd refused the job: $BOOTSTRAP_ERR" ;;
    esac
fi
launchctl kickstart -p "system/$DAEMON_ID" >/dev/null 2>&1 || true

# Poll rather than assume: bootstrap returning 0 means launchd accepted the
# job, not that the process started successfully.
for _ in $(seq 1 20); do
    if launchctl print "system/$DAEMON_ID" 2>/dev/null | grep -q "state = running"; then
        say "running"
        break
    fi
    sleep 0.5
done

echo
if launchctl print "system/$DAEMON_ID" 2>/dev/null | grep -q "state = running"; then
    PID=$(launchctl print "system/$DAEMON_ID" 2>/dev/null | awk '/^\tpid = /{print $3}')
    cat <<EOF
Installed.

  service   $DAEMON_ID (pid ${PID:-?})
  daemon    $LIBEXEC/nmcapd
  app       $INSTALLED_APP
  data      $DATA_ROOT

$INSTALLING_USER can read the logs directly; everyone else goes through the
service. Changing what is recorded will ask for an administrator.

  open $INSTALLED_APP
  log stream --predicate 'subsystem == "com.narusec.networkmonitor"' --level info
  sudo Tools/uninstall.sh
EOF
else
    cat <<EOF
The service was installed but is not running.

  launchctl print system/$DAEMON_ID
  cat $LOG_DIR/nmcapd.err
  log show --predicate 'subsystem == "com.narusec.networkmonitor"' --last 5m
EOF
    exit 1
fi
