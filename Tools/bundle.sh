#!/bin/bash
#
# bundle.sh -- assemble NetworkMonitor.app.
#
# SwiftPM builds the binary; this builds the bundle. That division is the whole
# packaging story on a machine with only the Command Line Tools: a bare Mach-O
# with @main will launch, but without a bundle Info.plist AppKit cannot
# determine the activation policy, so there is no Dock icon, the menu bar is
# degraded and keyboard focus is unreliable.
#
set -euo pipefail
cd "$(dirname "$0")/.."

CONFIGURATION="${1:-release}"
APP_NAME="NetworkMonitor"
BUNDLE="build/${APP_NAME}.app"
APP_ID="com.narusec.NetworkMonitor"
DAEMON_ID="com.narusec.networkmonitor.nmcapd"

echo "Building ($CONFIGURATION)..."
swift build -c "$CONFIGURATION" --product NetworkMonitorApp
swift build -c "$CONFIGURATION" --product nmcapd

BIN_DIR=".build/${CONFIGURATION}"

echo "Assembling $BUNDLE"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources" "$BUNDLE/Contents/Helpers"

cp "$BIN_DIR/NetworkMonitorApp" "$BUNDLE/Contents/MacOS/$APP_NAME"
cp "$BIN_DIR/nmcapd" "$BUNDLE/Contents/Helpers/nmcapd"
cp Tools/Resources/Info.plist "$BUNDLE/Contents/Info.plist"
printf 'APPL????' > "$BUNDLE/Contents/PkgInfo"

# plutil is available without Xcode and catches a malformed plist here rather
# than as a silent launch failure later.
plutil -lint "$BUNDLE/Contents/Info.plist" >/dev/null

# Icon, if a master image is present. sips and iconutil both ship with the
# Command Line Tools; actool does not, which is why there is no asset catalog.
if [ -f Tools/Resources/icon-1024.png ]; then
    ICONSET=$(mktemp -d)/AppIcon.iconset
    mkdir -p "$ICONSET"
    for size in 16 32 128 256 512; do
        sips -z $size $size Tools/Resources/icon-1024.png \
            --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
        sips -z $((size*2)) $((size*2)) Tools/Resources/icon-1024.png \
            --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
    done
    iconutil -c icns "$ICONSET" -o "$BUNDLE/Contents/Resources/AppIcon.icns"
    rm -rf "$(dirname "$ICONSET")"
else
    echo "  (no Tools/Resources/icon-1024.png -- the app will use the generic icon)"
fi

# Sign inner-out. Ad-hoc rather than unsigned even for local builds, because
# the XPC peer check needs a stable code identity to pin against; --identifier
# is given explicitly so the daemon's designated requirement does not depend on
# a path. --options runtime is deliberately omitted: the hardened runtime buys
# nothing without notarization and complicates debugging.
echo "Signing (ad-hoc)"
codesign --force --sign - --identifier "$DAEMON_ID" "$BUNDLE/Contents/Helpers/nmcapd"
codesign --force --sign - --identifier "$APP_ID" "$BUNDLE"
codesign --verify --strict --verbose=1 "$BUNDLE" 2>&1 | sed 's/^/  /'

APP_HASH=$(codesign -d --verbose=4 "$BUNDLE" 2>&1 | awk -F'=' '/^CDHash/{print $2}')
DAEMON_HASH=$(codesign -d --verbose=4 "$BUNDLE/Contents/Helpers/nmcapd" 2>&1 \
              | awk -F'=' '/^CDHash/{print $2}')

cat <<EOF

Built $BUNDLE
  app cdhash     ${APP_HASH:-unknown}
  daemon cdhash  ${DAEMON_HASH:-unknown}

Neither binary can contain the other's hash, so the install script writes both
to peers.plist and each reads its peer's requirement from there at startup.

Run it:   open $BUNDLE
EOF
