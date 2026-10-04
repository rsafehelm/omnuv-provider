#!/usr/bin/env bash
# The provider opening's rules, applied and removed by the packaged binary in
# a disposable privileged container (its own network namespace; nothing on
# this machine is touched), against the egress policy omnuv's play installs.
#
#     tests/opening/nft_test.sh <onv-provider binary> [egress.nft]
#
# The binary must run on Debian trixie: the one build-deb.sh builds does.
# egress.nft defaults to tests/opening/egress.nft, a rendering of omnuv's
# template that omnuv's opening_egress_test.py holds to it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
bin="$(realpath "$1")"
egress="$(realpath "${2:-$here/egress.nft}")"
# Default bridge network: apt needs the internet, and no network is created.
docker run --rm --privileged --name "onvt-opening-$$" \
    -v "$bin:/usr/local/bin/onv-provider:ro" \
    -v "$here/udp.py:/t/udp.py:ro" \
    -v "$here/in_container.sh:/t/in_container.sh:ro" \
    -v "$egress:/t/egress.nft:ro" \
    debian:trixie-slim bash -c '
        apt-get -qq update >/dev/null 2>&1 &&
        DEBIAN_FRONTEND=noninteractive apt-get -qq install -y nftables iproute2 python3-minimal >/dev/null 2>&1 ||
            { echo "FAIL  the test tools could not be installed"; exit 1; }
        bash /t/in_container.sh'
