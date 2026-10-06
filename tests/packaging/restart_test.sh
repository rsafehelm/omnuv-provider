#!/usr/bin/env bash
# One restart per upgrade (omnuv's modular design, A5), with the package
# itself, in a disposable container: nothing on this machine is touched.
#
#     tests/packaging/restart_test.sh <file.deb> [<postinst to use instead>]
#
# The package is installed with dpkg, as a host installs it, under a stub
# systemctl that records each verb and unit. Variants of it, each changing
# one thing, are made in the container from its raw contents with a new
# Version, and installed in turn; restart_in_container.sh says what each
# install must restart, and nothing else (tests/packaging/restart_in_container.sh).
#
# The second argument replaces the postinst in every variant, to show the
# test failing against the one it replaced (A5's acceptance): the postinst
# at 30371d4 restarts the agent on every configure.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
deb="$(realpath "$1")"
override=()
if [ -n "${2:-}" ]; then
    override=(-v "$(realpath "$2"):/t/postinst-override:ro")
fi
# Default bridge network: apt needs the internet for adduser, the package's
# one dependency the image lacks, and no network is created.
docker run --rm --name "onvt-restart-$$" \
    -v "$deb:/t/pkg.deb:ro" \
    "${override[@]}" \
    -v "$here/restart_in_container.sh:/t/restart_in_container.sh:ro" \
    debian:trixie-slim bash -c '
        apt-get -qq update >/dev/null 2>&1 &&
        DEBIAN_FRONTEND=noninteractive apt-get -qq install -y adduser >/dev/null 2>&1 ||
            { echo "FAIL  the test tools could not be installed"; exit 1; }
        bash /t/restart_in_container.sh'
