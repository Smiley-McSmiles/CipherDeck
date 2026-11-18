#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

VERSION="$(awk -F'"' '/^version = / { print $2; exit }' Cargo.toml)"
UNAME_ARCH="$(uname -m)"

case "$UNAME_ARCH" in
    x86_64)
        DEB_ARCH="amd64"
        RPM_ARCH="x86_64"
        TAR_ARCH="x86_64"
        ;;
    aarch64|arm64)
        DEB_ARCH="arm64"
        RPM_ARCH="aarch64"
        TAR_ARCH="aarch64"
        ;;
    *)
        DEB_ARCH="$UNAME_ARCH"
        RPM_ARCH="$UNAME_ARCH"
        TAR_ARCH="$UNAME_ARCH"
        ;;
esac

APP_ID="io.github.woosah.CipherDeck"
ICON_SRC="$ROOT_DIR/data/icons/hicolor/scalable/apps/${APP_ID}.svg"
DESKTOP_SRC="$ROOT_DIR/data/${APP_ID}.desktop"
DIST_DIR="$ROOT_DIR/dist"
STAGE_ROOT="$(mktemp -d)"
trap 'rm -rf "$STAGE_ROOT"' EXIT

echo "==> Building release binary (cipherdeck) v${VERSION}..."
cargo build --release -p cipherdeck -j "${CARGO_BUILD_JOBS:-2}"

BIN_PATH="$ROOT_DIR/target/release/cipherdeck"

if [[ ! -x "$BIN_PATH" ]]; then
    echo "Error: release binary not found in target/release/" >&2
    exit 1
fi

if command -v strip >/dev/null 2>&1; then
    strip --strip-unneeded "$BIN_PATH" || true
fi

if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$DESKTOP_SRC"
fi

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# -----------------------------------------------------------------------------
# 1. Generic Linux tarball (.tar.gz) with install.sh
# -----------------------------------------------------------------------------
TAR_NAME="cipherdeck-${VERSION}-linux-${TAR_ARCH}"
TAR_STAGE="$STAGE_ROOT/$TAR_NAME"
mkdir -p "$TAR_STAGE/bin" "$TAR_STAGE/share/applications" "$TAR_STAGE/share/icons/hicolor/scalable/apps"

cp "$BIN_PATH" "$TAR_STAGE/bin/cipherdeck"
cp "$DESKTOP_SRC" "$TAR_STAGE/share/applications/${APP_ID}.desktop"
cp "$ICON_SRC" "$TAR_STAGE/share/icons/hicolor/scalable/apps/${APP_ID}.svg"
cp "$ROOT_DIR/LICENSE" "$TAR_STAGE/LICENSE"
cp "$ROOT_DIR/README.md" "$TAR_STAGE/README.md"

cat > "$TAR_STAGE/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ID="io.github.woosah.CipherDeck"

if [[ "${1:-}" == "--prefix" && -n "${2:-}" ]]; then
    PREFIX="$2"
elif [[ "$(id -u)" -eq 0 ]]; then
    PREFIX="/usr/local"
else
    PREFIX="${HOME}/.local"
fi

if [[ "${1:-}" == "--uninstall" || "${3:-}" == "--uninstall" ]]; then
    rm -f "${PREFIX}/bin/cipherdeck" \
          "${PREFIX}/share/applications/${APP_ID}.desktop" \
          "${PREFIX}/share/icons/hicolor/scalable/apps/${APP_ID}.svg"
    echo "Uninstalled CipherDeck from ${PREFIX}"
    exit 0
fi

install -Dm755 "$SCRIPT_DIR/bin/cipherdeck" "${PREFIX}/bin/cipherdeck"
install -Dm644 "$SCRIPT_DIR/share/applications/${APP_ID}.desktop" "${PREFIX}/share/applications/${APP_ID}.desktop"
install -Dm644 "$SCRIPT_DIR/share/icons/hicolor/scalable/apps/${APP_ID}.svg" "${PREFIX}/share/icons/hicolor/scalable/apps/${APP_ID}.svg"

if command -v gtk4-update-icon-cache >/dev/null 2>&1; then
    gtk4-update-icon-cache -f -t "${PREFIX}/share/icons/hicolor" 2>/dev/null || true
elif command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "${PREFIX}/share/icons/hicolor" 2>/dev/null || true
fi

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "${PREFIX}/share/applications" 2>/dev/null || true
fi

echo "Installed CipherDeck to ${PREFIX}"
echo "Make sure ${PREFIX}/bin is in your PATH."
EOF
chmod +x "$TAR_STAGE/install.sh"

tar -C "$STAGE_ROOT" -czf "$DIST_DIR/${TAR_NAME}.tar.gz" "$TAR_NAME"
echo "==> Created $DIST_DIR/${TAR_NAME}.tar.gz"

# -----------------------------------------------------------------------------
# 2. Debian package (.deb)
# -----------------------------------------------------------------------------
if command -v dpkg-deb >/dev/null 2>&1; then
    DEB_NAME="cipherdeck_${VERSION}_${DEB_ARCH}"
    DEB_STAGE="$STAGE_ROOT/$DEB_NAME"
    mkdir -p "$DEB_STAGE/DEBIAN" \
             "$DEB_STAGE/usr/bin" \
             "$DEB_STAGE/usr/share/applications" \
             "$DEB_STAGE/usr/share/icons/hicolor/scalable/apps" \
             "$DEB_STAGE/usr/share/doc/cipherdeck"

    install -m755 "$BIN_PATH" "$DEB_STAGE/usr/bin/cipherdeck"
    install -m644 "$DESKTOP_SRC" "$DEB_STAGE/usr/share/applications/${APP_ID}.desktop"
    install -m644 "$ICON_SRC" "$DEB_STAGE/usr/share/icons/hicolor/scalable/apps/${APP_ID}.svg"
    install -m644 "$ROOT_DIR/LICENSE" "$DEB_STAGE/usr/share/doc/cipherdeck/copyright"

    cat > "$DEB_STAGE/DEBIAN/control" <<EOF
Package: cipherdeck
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: Woosah <https://GitHub.com/Smiley-McSmiles/CipherDeck>
Depends: libgtk-4-1, libadwaita-1-0
Homepage: https://GitHub.com/Smiley-McSmiles/CipherDeck
Description: Cascade-encrypted password and Markdown note vault
 Offline-first GTK 4 / Libadwaita password manager and Markdown note vault
 using Argon2id, AES-256-GCM + XChaCha20-Poly1305 cascade encryption,
 Ed25519 signatures, and field-level CRDT sync.
EOF

    dpkg-deb --build --root-owner-group "$DEB_STAGE" "$DIST_DIR/${DEB_NAME}.deb"
    echo "==> Created $DIST_DIR/${DEB_NAME}.deb"
else
    echo "Warning: dpkg-deb not found; skipping .deb build" >&2
fi

# -----------------------------------------------------------------------------
# 3. RPM package (.rpm)
# -----------------------------------------------------------------------------
if command -v rpmbuild >/dev/null 2>&1; then
    RPM_TOP="$STAGE_ROOT/rpmbuild"
    mkdir -p "$RPM_TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

    cat > "$RPM_TOP/SPECS/cipherdeck.spec" <<EOF
%global debug_package %{nil}

Name:           cipherdeck
Version:        ${VERSION}
Release:        1
Summary:        Cascade-encrypted password and Markdown note vault
License:        MIT
URL:            https://GitHub.com/Smiley-McSmiles/CipherDeck
Requires:       gtk4, libadwaita

%description
Offline-first GTK 4 / Libadwaita password manager and Markdown note vault
using Argon2id, AES-256-GCM + XChaCha20-Poly1305 cascade encryption,
Ed25519 signatures, and field-level CRDT sync.

%install
install -Dm755 "${BIN_PATH}" "%{buildroot}%{_bindir}/cipherdeck"
install -Dm644 "${DESKTOP_SRC}" "%{buildroot}%{_datadir}/applications/${APP_ID}.desktop"
install -Dm644 "${ICON_SRC}" "%{buildroot}%{_datadir}/icons/hicolor/scalable/apps/${APP_ID}.svg"
install -Dm644 "${ROOT_DIR}/LICENSE" "%{buildroot}%{_licensedir}/%{name}/LICENSE"

%files
%{_bindir}/cipherdeck
%{_datadir}/applications/${APP_ID}.desktop
%{_datadir}/icons/hicolor/scalable/apps/${APP_ID}.svg
%{_licensedir}/%{name}/LICENSE

%changelog
* $(date "+%a %b %d %Y") Woosah <https://GitHub.com/Smiley-McSmiles/CipherDeck> - ${VERSION}-1
- Initial package release
EOF

    rpmbuild --define "_topdir ${RPM_TOP}" --target "${RPM_ARCH}" -bb "$RPM_TOP/SPECS/cipherdeck.spec"
    find "$RPM_TOP/RPMS" -name "*.rpm" -exec cp {} "$DIST_DIR/" \;
    echo "==> Created RPM in $DIST_DIR/"
else
    echo "Warning: rpmbuild not found; skipping .rpm build" >&2
fi

echo ""
echo "Done! Artifacts in $DIST_DIR:"
ls -lh "$DIST_DIR"
