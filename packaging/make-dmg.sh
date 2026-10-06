#!/bin/bash
# Build a drag-to-Applications disk image for this Mac.
# The binary is the architecture of the machine that runs this script.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
source "$HOME/.cargo/env"

cd "$root"
cargo build --release -p watcher-desktop --bin app-network-watcher

binary="$root/target/release/app-network-watcher"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -n 1)"
arch="$(uname -m)"
app_name="App Network Watcher"
dist="$root/dist"
stage="$dist/stage"
app="$stage/$app_name.app"

rm -rf "$stage"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$binary" "$app/Contents/MacOS/app-network-watcher"
chmod 755 "$app/Contents/MacOS/app-network-watcher"
sed "s/0\\.1\\.0/$version/g" "$root/packaging/Info.plist" > "$app/Contents/Info.plist"
if [[ -f "$root/packaging/AppIcon.icns" ]]; then
  cp "$root/packaging/AppIcon.icns" "$app/Contents/Resources/AppIcon.icns"
fi

# Ad-hoc signature so Apple Silicon will launch the bundle. It is not an
# Apple Developer ID signature, so the first open uses the Open shortcut.
codesign --force --deep --sign - "$app"
codesign --verify --verbose=2 "$app"

ln -s /Applications "$stage/Applications"

dmg="$dist/App Network Watcher-${version}-${arch}.dmg"
rm -f "$dmg"
hdiutil create \
  -volname "$app_name" \
  -srcfolder "$stage" \
  -ov \
  -format UDZO \
  "$dmg"

echo "Wrote $dmg"
hdiutil verify "$dmg"
ls -lh "$dmg"
