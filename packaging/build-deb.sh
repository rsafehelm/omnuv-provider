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
CRATE="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
# **The version has to move when the bytes move.** The crate version does not
# change between iterations, so two different binaries called themselves the
# same thing and `apt` — which decides by version — installed neither. On 12
# September that meant a fix was built, committed, deployed to both providers,
# and the failure reproduced exactly, because what reached the hosts was the
# package from an hour before.
#
# `+g<sha>` is a Debian-legal suffix that sorts above the bare version, and
# `git describe --dirty` appends `-dirty` when the tree is not clean — so a
# package built from uncommitted work is distinguishable too, rather than
# silently identical to the commit it came from.
BUILD="$(cd "$ROOT" && git describe --always --dirty --abbrev=7 2>/dev/null || echo unknown)"
VERSION="${CRATE}+g${BUILD}"
if [ -n "${1:-}" ] && [ "$1" != "$CRATE" ] && [ "$1" != "$VERSION" ]; then
    echo "Cargo.toml says $CRATE (package $VERSION), not $1." >&2
    exit 2
fi
OUT="$ROOT/dist"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
STAGE="$OUT/.deb"

echo "onv-provider $VERSION ($ARCH)"

# A release build, statically enough linked for any current Debian or Ubuntu:
# the agent speaks TLS through rustls rather than the system OpenSSL, so the
# only real link is glibc.
docker run --rm -v "$ROOT:/w" -v omnuv_cargo-registry:/usr/local/cargo/registry \
    -e OMNUV_BUILD="$VERSION" -w /w rust:1.98 cargo build --release --quiet

rm -rf "$STAGE"
mkdir -p "$STAGE/usr/bin" "$STAGE/usr/share/doc/onv-provider"
cp -r "$ROOT/packaging/deb/DEBIAN" "$STAGE/"
cp -r "$ROOT/packaging/deb/lib" "$STAGE/"
install -m 0755 "$ROOT/target/release/onv-provider" "$STAGE/usr/bin/onv-provider"
install -m 0644 "$ROOT/README.md" "$STAGE/usr/share/doc/onv-provider/README.md"
install -m 0644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/onv-provider/copyright"

size=$(du -sk "$STAGE" | cut -f1)
cat > "$STAGE/DEBIAN/control" <<CTL
Package: onv-provider
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Depends: libc6, adduser
Installed-Size: $size
Maintainer: Omnuv <ops@omnuv.com>
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
 Enrol a machine with: onv-provider join --token <token>
CTL

docker run --rm -v "$OUT:/out" -w /out debian:trixie-slim sh -c "
    apt-get -qq update >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y fakeroot >/dev/null 2>&1
    fakeroot dpkg-deb --build .deb onv-provider_${VERSION}_${ARCH}.deb
    rm -rf /out/.deb
" >/dev/null

# A stable name for the deploy to install, beside the versioned one it keeps.
# The play cannot guess `+g<sha>`, and hard-coding a version there would be the
# same one-definition-in-two-places mistake that produced this bug.
cp "$OUT/onv-provider_${VERSION}_${ARCH}.deb" "$OUT/onv-provider_current_${ARCH}.deb"

echo "  $(basename "$OUT")/onv-provider_${VERSION}_${ARCH}.deb"
