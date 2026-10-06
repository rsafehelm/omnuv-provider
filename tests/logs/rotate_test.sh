#!/usr/bin/env bash
# The package's log bounds and its agent unit, in a disposable container
# (omnuv's modular design, A4): nothing on this machine is touched.
#
#     tests/logs/rotate_test.sh <the package's extracted root> <its postinst>
#
#   - logrotate, with the package's own file, rotates /var/log/onv as the
#     package and deploy-agent.yml leave it (onv:adm 0750, the audit log
#     onv:onv 0640), and the new audit.log keeps that owner and mode;
#   - the packaged host timer (onv-lease-expire, A3), as onv, then appends
#     to the new audit.log and not to the rotated one;
#   - systemd-analyze verify loads each of the package's three services with
#     nothing to say, so a directive it does not know, or a value it cannot
#     parse, fails;
#   - the package's postinst, under a stub systemctl, restarts journald on a
#     first install, not on an unchanged reconfigure, again after the cap is
#     edited, and records nothing when the restart fails.
#
# The binary must run on Debian trixie: the one build-deb.sh builds does.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(realpath "$1")"
postinst="$(realpath "$2")"
# Default bridge network: apt needs the internet, and no network is created.
docker run --rm --name "onvt-logs-$$" \
    -v "$root:/pkg:ro" \
    -v "$postinst:/t/postinst:ro" \
    -v "$here/in_container.sh:/t/in_container.sh:ro" \
    debian:trixie-slim bash -c '
        apt-get -qq update >/dev/null 2>&1 &&
        DEBIAN_FRONTEND=noninteractive apt-get -qq install -y logrotate systemd >/dev/null 2>&1 ||
            { echo "FAIL  the test tools could not be installed"; exit 1; }
        bash /t/in_container.sh'
