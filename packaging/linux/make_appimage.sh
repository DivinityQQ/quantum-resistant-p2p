#!/bin/sh
# Wrap a Linux build (packaging/build.py) in an AppImage: packaging/linux/make_appimage.sh DIST OUT
# Needs appimagetool on PATH (https://github.com/AppImage/appimagetool); unsigned, for testing.
set -eu
dist=$1
out=$2
here="$(dirname "$(readlink -f "$0")")"
app="$(mktemp -d)/QRP2P.AppDir"
mkdir -p "$app/usr/lib"
cp -a "$dist" "$app/usr/lib/qrp2p"
cp "$here/AppRun" "$app/AppRun"
cp "$here/qrp2p.desktop" "$app/qrp2p.desktop"
cp "$dist/qrp2p/ui/resources/app-icon.png" "$app/qrp2p.png"
ARCH="$(uname -m)" appimagetool --no-appstream "$app" "$out"
