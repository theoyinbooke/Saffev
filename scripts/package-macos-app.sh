#!/usr/bin/env bash
#
# Build Saffev.app — a double-click macOS menu-bar launcher.
#
# It bundles the release `saffev` binary (built with the `tray` feature) and runs
# `saffev tray`: a menu-bar item that keeps the proxy + Studio running and offers
# Open Studio / Start-Stop-Restart / Open at Login / Quit. No terminal required.
#
# Usage:
#   scripts/package-macos-app.sh [--sign "Developer ID Application: NAME (TEAMID)"]
#                                [--notarize KEYCHAIN_PROFILE]
#                                [--keychain /path/to/signing.keychain-db]
#
# --keychain pins which keychain holds the identity and the notarytool profile.
# Needed in CI, where the certificate is imported into a throwaway keychain rather
# than the login one. Omit it locally to use the default search list.
#
# --notarize requires --sign and a notarytool keychain profile created once via:
#   xcrun notarytool store-credentials PROFILE \
#     --apple-id YOU@example.com --team-id TEAMID --password APP_SPECIFIC_PW
#
# Output: target/Saffev.app  (drag it to /Applications, then double-click).
#         With --notarize, also target/Saffev-macos-<arch>.dmg — a notarized,
#         stapled drag-install disk image (the primary download; no unzip).
set -euo pipefail
cd "$(dirname "$0")/.."

SIGN_ID=""
NOTARY_PROFILE=""
KEYCHAIN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sign)     SIGN_ID="${2:?--sign needs an identity}"; shift 2 ;;
    --notarize) NOTARY_PROFILE="${2:?--notarize needs a keychain profile}"; shift 2 ;;
    --keychain) KEYCHAIN="${2:?--keychain needs a path}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -n "$NOTARY_PROFILE" && -z "$SIGN_ID" ]]; then
  echo "--notarize requires --sign (notarytool rejects unsigned apps)" >&2
  exit 2
fi

VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
APP="target/Saffev.app"
BIN="target/release/saffev"

echo "==> Building release binary with the tray feature (SQLCipher + vendored OpenSSL)…"
cargo build --release --features tray

echo "==> Assembling $APP (v$VERSION)…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# The binary IS the bundle executable — when launched from the .app with no
# subcommand it runs `tray` (see main.rs). No separate launcher script: on the
# case-insensitive macOS filesystem `saffev` and `Saffev` would collide.
cp "$BIN" "$APP/Contents/MacOS/saffev"
chmod +x "$APP/Contents/MacOS/saffev"

# Info.plist — LSUIElement makes it a menu-bar-only agent (no Dock icon).
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Saffev</string>
  <key>CFBundleDisplayName</key><string>Saffev</string>
  <key>CFBundleIdentifier</key><string>com.saffev.launcher</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleExecutable</key><string>saffev</string>
  <key>CFBundleIconFile</key><string>Saffev</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><true/>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST

# App icon (best-effort): draw the Saffev target as a PNG (pure-stdlib Python),
# fan out to an .iconset with sips, then iconutil -> .icns. Skipped if tools are
# missing (the app still works, just with a generic icon).
if command -v python3 >/dev/null && command -v sips >/dev/null && command -v iconutil >/dev/null; then
  echo "==> Generating app icon…"
  TMP="$(mktemp -d)"
  python3 - "$TMP/icon.png" <<'PY'
import zlib, struct, sys, math
W = H = 1024
rows = bytearray()
cx = cy = W / 2.0
for y in range(H):
    rows.append(0)  # PNG filter type 0 per scanline
    for x in range(W):
        d = math.hypot(x - cx, y - cy)
        ring = (W * 0.27) <= d <= (W * 0.40)
        dot = d <= (W * 0.13)
        rows += bytes((15, 118, 110, 255)) if (ring or dot) else bytes((0, 0, 0, 0))
def chunk(t, d):
    return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
png = b'\x89PNG\r\n\x1a\n'
png += chunk(b'IHDR', struct.pack('>IIBBBBB', W, H, 8, 6, 0, 0, 0))
png += chunk(b'IDAT', zlib.compress(bytes(rows), 9))
png += chunk(b'IEND', b'')
open(sys.argv[1], 'wb').write(png)
PY
  ICONSET="$TMP/Saffev.iconset"; mkdir -p "$ICONSET"
  for s in 16 32 128 256 512; do
    sips -z "$s" "$s" "$TMP/icon.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    sips -z "$((s * 2))" "$((s * 2))" "$TMP/icon.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/Saffev.icns"
  rm -rf "$TMP"
else
  echo "   (skipping icon: python3/sips/iconutil not all available)"
fi

# Codesign if a Developer ID was supplied (unsigned still runs after a
# right-click -> Open on first launch). --timestamp is required: notarytool
# rejects signatures without a secure timestamp.
if [[ -n "$SIGN_ID" ]]; then
  echo "==> Codesigning with: $SIGN_ID"
  codesign --force --options runtime --timestamp \
    ${KEYCHAIN:+--keychain "$KEYCHAIN"} --sign "$SIGN_ID" "$APP"
  codesign --verify --deep --strict "$APP" && echo "   signature OK"
fi

# Notarize the app, staple it, then wrap it in a notarized drag-install DMG
# (needs --sign and a stored notarytool keychain profile). notarytool needs a
# container (zip/dmg), so the app is submitted zipped; the DMG is submitted and
# stapled separately so Gatekeeper accepts the downloaded .dmg with no unzip.
ARCH="$(uname -m)"  # arm64 on Apple Silicon; the release asset is named by arch.
DMG="target/Saffev-macos-$ARCH.dmg"
if [[ -n "$NOTARY_PROFILE" ]]; then
  echo "==> Notarizing app (profile: $NOTARY_PROFILE)…"
  ZIP="target/Saffev-$VERSION.zip"
  rm -f "$ZIP"
  ditto -c -k --keepParent "$APP" "$ZIP"
  xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" \
    ${KEYCHAIN:+--keychain "$KEYCHAIN"} --wait
  xcrun stapler staple "$APP"
  rm -f "$ZIP"

  echo "==> Building drag-install DMG: ${DMG}…"
  STAGE="$(mktemp -d)"
  cp -R "$APP" "$STAGE/"
  ln -s /Applications "$STAGE/Applications"   # drag Saffev.app -> Applications
  rm -f "$DMG"
  hdiutil create -volname "Saffev" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
  rm -rf "$STAGE"

  # Sign the DMG itself (not just the app inside) so Gatekeeper has a usable
  # primary signature on the downloaded image, then notarize + staple it.
  echo "==> Signing + notarizing DMG…"
  codesign --force --timestamp ${KEYCHAIN:+--keychain "$KEYCHAIN"} --sign "$SIGN_ID" "$DMG"
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" \
    ${KEYCHAIN:+--keychain "$KEYCHAIN"} --wait
  xcrun stapler staple "$DMG"
  spctl -a -t open --context context:primary-signature -vv "$DMG" \
    && echo "   DMG notarization OK (Gatekeeper accepts the download)"
fi

echo ""
echo "Built $APP"

# Only claim the DMG when THIS run actually produced it. The DMG is built inside
# the --notarize branch above, but `target/` is not cleaned between runs, so a
# stale image from an earlier version can sit there for months. Reporting "Built
# <dmg>" because the file merely exists is how a months-old binary gets uploaded
# under a new release tag — a far worse outcome than having no DMG at all.
if [[ -n "$NOTARY_PROFILE" ]]; then
  echo "Built $DMG  (drag-install: open it, drag Saffev.app to Applications)"
elif [[ -f "$DMG" ]]; then
  STALE_VER="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$APP/Contents/Info.plist" 2>/dev/null || echo '?')"
  echo ""
  echo "NOTE: $DMG exists but was NOT rebuilt by this run (no --notarize)."
  echo "      It is left over from an earlier build and may contain an older"
  echo "      version than the $STALE_VER app just built. Do NOT ship it."
  echo "      Re-run with --sign and --notarize to produce a current DMG."
fi

echo "  Install:  cp -R \"$APP\" /Applications/  &&  open /Applications/Saffev.app"
echo "  It appears in the menu bar (no Dock icon). Click it -> Open Saffev Studio."
