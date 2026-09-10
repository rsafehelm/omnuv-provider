#!/usr/bin/env bash
# Builds the Provider Agent as a Debian package.
#
#     ./packaging/build-deb.sh [version]
#
# Built in a container, so the machine doing it needs Docker and nothing else:
# no Rust toolchain, no root, and the same result on any host.
#
# The package deliberately declares no dependency on a hypervisor. The driver
# layer exists so that a second runtime can arrive, and a package that requires
# Proxmox is a package that cannot be installed on a Kubernetes provider.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# One source of truth. The agent reports CARGO_PKG_VERSION to Core, so a version
# passed on the command line would produce a package whose number disagreed with
# what the running agent says it is — which is precisely the number the runtime
# compatibility profiles are written against.
VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
if [ -n "${1:-}" ] && [ "$1" != "$VERSION" ]; then
    echo "Cargo.toml says $VERSION, not $1. Bump the crate version instead." >&2
    exit 2
fi
OUT="$ROOT/dist"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
STAGE="$OUT/.deb"

echo "omnuv-provider $VERSION ($ARCH)"

# A release build, statically enough linked for any current Debian or Ubuntu:
# the agent speaks TLS through rustls rather than the system OpenSSL, so the
# only real link is glibc.
docker run --rm -v "$ROOT:/w" -v omnuv_cargo-registry:/usr/local/cargo/registry \
    -w /w rust:1.98 cargo build --release --quiet

rm -rf "$STAGE"
mkdir -p "$STAGE/usr/bin" "$STAGE/usr/share/doc/omnuv-provider"
cp -r "$ROOT/packaging/deb/DEBIAN" "$STAGE/"
cp -r "$ROOT/packaging/deb/lib" "$STAGE/"
install -m 0755 "$ROOT/target/release/omnuv-provider" "$STAGE/usr/bin/omnuv-provider"
install -m 0644 "$ROOT/README.md" "$STAGE/usr/share/doc/omnuv-provider/README.md"
install -m 0644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/omnuv-provider/copyright"

size=$(du -sk "$STAGE" | cut -f1)
cat > "$STAGE/DEBIAN/control" <<CTL
Package: omnuv-provider
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Depends: libc6, adduser
Installed-Size: $size
Maintainer: Omnuv <ops@omnuv.dev>
Homepage: https://github.com/rsafehelm/omnuv-provider
Description: Omnuv Provider Agent
 Marketplace-owned software that runs inside a provider's own environment,
 reconciles that provider's runtime toward the state Omnuv asks for, and
 reports back what is actually true.
 .
 It never listens: every connection is outbound. Hypervisor credentials are
 created locally at enrolment and never leave the machine. While Core is
 unreachable it maintains what is running and decides nothing.
 .
 Enrol a machine with: omnuv-provider join --token <token>
CTL

docker run --rm -v "$OUT:/out" -w /out debian:trixie-slim sh -c "
    apt-get -qq update >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y fakeroot >/dev/null 2>&1
    fakeroot dpkg-deb --build .deb omnuv-provider_${VERSION}_${ARCH}.deb
    rm -rf /out/.deb
" >/dev/null

echo "  $(basename "$OUT")/omnuv-provider_${VERSION}_${ARCH}.deb"
