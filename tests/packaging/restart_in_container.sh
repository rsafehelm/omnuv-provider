#!/usr/bin/env bash
# Run by restart_test.sh inside its container, as root. /t/pkg.deb is the
# package; /t/postinst-override, when mounted, replaces its postinst.
#
# Every case runs and says ok or FAIL, and the run fails if any did, so a
# postinst that is wrong in several ways says each of them.
set -euo pipefail
bad=0
fail() { echo "FAIL  $*"; bad=1; }
ok() { echo "ok    $*"; }

# **The stub.** systemd is not installed, so this is the only systemctl;
# /usr/local/sbin is first on dpkg's PATH for maintainer scripts. It records
# `<verb> <unit>` per call, and fails the call written in /tmp/stub/fail.
# /run/systemd/system makes the postinst believe systemd runs.
mkdir -p /tmp/stub /run/systemd/system
cat > /usr/local/sbin/systemctl <<'STUB'
#!/bin/sh
echo "$*" >> /tmp/stub/calls
if [ -f /tmp/stub/fail ] && [ "$*" = "$(cat /tmp/stub/fail)" ]; then exit 1; fi
exit 0
STUB
chmod 0755 /usr/local/sbin/systemctl

# **The variants**, each from the one before with one thing changed and a
# Version of its own, as a rebuild with that change would be.
#   a  the package as built
#   b  a's onv-opening binary changed
#   c  b's onv-opening.service changed
#   d  c's onv-provider.service changed
mkdir -p /t/v
dpkg-deb -R /t/pkg.deb /t/v/a
if [ -f /t/postinst-override ]; then
    install -m 0755 /t/postinst-override /t/v/a/DEBIAN/postinst
    echo "using the postinst given in place of the package's"
fi
version="$(dpkg-deb -f /t/pkg.deb Version)"
variant() { # <from> <to> <file to change>
    cp -a "/t/v/$1" "/t/v/$2"
    printf '\n# changed for variant %s\n' "$2" >> "/t/v/$2/$3"
    sed -i "s/^Version: .*/Version: $version.t$2/" "/t/v/$2/DEBIAN/control"
}
variant a b usr/bin/onv-opening
variant b c lib/systemd/system/onv-opening.service
variant c d lib/systemd/system/onv-provider.service
for v in a b c d; do
    dpkg-deb --root-owner-group -b "/t/v/$v" "/t/$v.deb" > /dev/null
done

# **What a configure restarted.** A restart is any verb that stops or starts
# a running unit; `enable --now` is not counted, since it starts a unit only
# if it is not running and every configure has always run it on the timer
# and the path unit.
VERBS='(restart|try-restart|start|stop|reload|reload-or-restart|try-reload-or-restart|condrestart)'
install_pkg() { # <variant>
    : > /tmp/stub/calls
    DEBIAN_FRONTEND=noninteractive dpkg -i "/t/$1.deb" > /tmp/dpkg.out 2>&1 \
        || { cat /tmp/dpkg.out; fail "dpkg -i $1 exited non-zero"; }
}
count() { # <unit>: the restarts of it in the last install
    grep -Ecx "$VERBS $1" /tmp/stub/calls || true
}
expect() { # <case> <unit>=<n>...: each unit restarted exactly n times
    local what="$1" u n got wrong=""
    shift
    for pair in "$@"; do
        u="${pair%=*}" n="${pair#*=}"
        got="$(count "$u")"
        [ "$got" = "$n" ] || wrong="$wrong $u restarted $got times, not $n;"
    done
    if [ -n "$wrong" ]; then
        echo "      systemctl calls:"; sed 's/^/        /' /tmp/stub/calls
        fail "$what:$wrong"
    else
        ok "$what"
    fi
}
record() { awk -v u="$1" '$1 == u { print $2 }' /var/lib/onv/units.sha256 2>/dev/null || true; }
ALL_NONE=(onv-provider.service=0 onv-opening.service=0 onv-opening.path=0
          onv-lease-expire.service=0 onv-lease-expire.timer=0 systemd-journald.service=0)

# A joined host: the agent has a configuration, so it runs.
mkdir -p /etc/onv
printf 'core:\n  url: https://core.invalid\n' > /etc/onv/agent.yaml

install_pkg a
expect "a first install restarts each unit once" \
    onv-provider.service=1 onv-opening.service=1 onv-lease-expire.timer=1 \
    systemd-journald.service=1 onv-lease-expire.service=0
for u in onv-provider.service onv-opening.service onv-lease-expire.timer; do
    [ -n "$(record "$u")" ] || fail "a first install recorded no sum for $u"
done

install_pkg a
expect "the same package again restarts nothing" "${ALL_NONE[@]}"

provider_before="$(record onv-provider.service)"
opening_before="$(record onv-opening.service)"
install_pkg b
expect "only onv-opening's binary changed: only onv-opening restarts" \
    onv-opening.service=1 onv-provider.service=0 onv-lease-expire.service=0 \
    onv-lease-expire.timer=0 systemd-journald.service=0
[ "$(record onv-provider.service)" = "$provider_before" ] || fail "the agent's recorded sum moved with onv-opening's binary"
[ "$(record onv-opening.service)" != "$opening_before" ] || fail "onv-opening's new sum was not recorded"
reload="$(grep -nx 'daemon-reload' /tmp/stub/calls | head -1 | cut -d: -f1)"
restart="$(grep -nEx "$VERBS onv-opening.service" /tmp/stub/calls | head -1 | cut -d: -f1)"
if [ -n "$reload" ] && [ -n "$restart" ] && [ "$reload" -lt "$restart" ]; then
    ok "daemon-reload ran before onv-opening's restart"
else
    fail "no daemon-reload before onv-opening's restart (reload at line ${reload:-none}, restart at ${restart:-none})"
fi

install_pkg c
expect "only onv-opening.service changed: only onv-opening restarts" \
    onv-opening.service=1 onv-provider.service=0 onv-lease-expire.service=0 \
    onv-lease-expire.timer=0 systemd-journald.service=0

# A drop-in the host adds is part of what the agent runs.
mkdir -p /etc/systemd/system/onv-provider.service.d
printf '[Service]\nEnvironment=ONV_TEST=1\n' > /etc/systemd/system/onv-provider.service.d/50-test.conf
install_pkg c
expect "a drop-in for the agent added: only the agent restarts" \
    onv-provider.service=1 onv-opening.service=0 onv-lease-expire.timer=0 systemd-journald.service=0

# A restart that fails records nothing, and the next configure tries again.
echo 'restart onv-provider.service' > /tmp/stub/fail
provider_before="$(record onv-provider.service)"
install_pkg d
expect "the agent's unit changed and its restart fails: tried once" \
    onv-provider.service=1 onv-opening.service=0 onv-lease-expire.timer=0
[ "$(record onv-provider.service)" = "$provider_before" ] || fail "a failed restart recorded the agent's new sum"
grep -q 'onv-provider.service is tried again' /tmp/dpkg.out || fail "a failed restart was not said"
rm /tmp/stub/fail
install_pkg d
expect "the configure after a failed restart restarts the agent" \
    onv-provider.service=1 onv-opening.service=0 onv-lease-expire.timer=0
install_pkg d
expect "and the one after that restarts nothing" "${ALL_NONE[@]}"

# Not joined: a changed agent is restarted only if it runs, never started.
rm /etc/onv/agent.yaml
install_pkg c
if grep -qx 'restart onv-provider.service' /tmp/stub/calls; then
    fail "a host that is not joined had its agent started"
elif grep -qx 'try-restart onv-provider.service' /tmp/stub/calls; then
    ok "not joined: a changed agent is try-restarted, never started"
else
    fail "not joined: a changed agent was not try-restarted"
fi

if [ "$bad" -ne 0 ]; then
    echo "restart: some cases failed"
    exit 1
fi
echo "restart: every case passed"
