#!/usr/bin/env bash
# Run by rotate_test.sh inside its container, as root; /pkg is the package.
set -euo pipefail
fail() { echo "FAIL  $*"; exit 1; }
ok() { echo "ok    $*"; }

addgroup --system onv >/dev/null
adduser --system --ingroup onv --no-create-home --home /var/lib/onv --shell /usr/sbin/nologin onv >/dev/null
install -m 0755 /pkg/usr/bin/onv-provider /usr/bin/onv-provider
install -m 0644 /pkg/etc/logrotate.d/onv-provider /etc/logrotate.d/onv-provider
install -d -o onv -g adm -m 0750 /var/log/onv
install -d -o onv -g onv /var/lib/onv
printf '{"subject":"before-the-rotation"}\n' > /var/log/onv/audit.log
chown onv:onv /var/log/onv/audit.log
chmod 0640 /var/log/onv/audit.log

logrotate -f -s /tmp/logrotate.state /etc/logrotate.d/onv-provider > /tmp/rotate.out 2>&1 \
    || { cat /tmp/rotate.out; fail "logrotate refused the package's file"; }
[ -s /tmp/rotate.out ] && { cat /tmp/rotate.out; fail "logrotate said something"; }
grep -q before-the-rotation /var/log/onv/audit.log.1 || fail "audit.log was not rotated to audit.log.1"
[ -f /var/log/onv/audit.log ] || fail "no new audit.log after the rotation"
grep -q before-the-rotation /var/log/onv/audit.log && fail "the new audit.log holds the old records"
got="$(stat -c '%U:%G %a' /var/log/onv/audit.log)"
[ "$got" = "onv:onv 640" ] || fail "the new audit.log is $got, not onv:onv 640"
ok "logrotate rotated audit.log by rename and made it again as onv:onv 0640"

# The host timer refuses root; as onv, against a configuration that is not
# there, it refuses and says so in the audit log (packaging/check.sh).
rc=0
setpriv --reuid onv --regid onv --init-groups \
    env OMNUV_LEASE_TIMER_LOG=/var/log/onv/run-lease-expire.log \
    /usr/bin/onv-provider run-lease-expire --config /nonexistent.yaml > /tmp/timer.out 2>&1 || rc=$?
[ "$rc" -eq 1 ] || { cat /tmp/timer.out; fail "the host timer exited $rc, not 1"; }
grep -q '"actor":"host-timer"' /var/log/onv/audit.log || fail "the agent wrote nothing to the new audit.log"
grep -q '"actor":"host-timer"' /var/log/onv/audit.log.1 && fail "the agent wrote to the rotated file"
ok "the packaged binary appends to the new audit.log, as onv"

systemd-analyze verify /pkg/lib/systemd/system/onv-provider.service > /tmp/verify.out 2>&1 \
    || { cat /tmp/verify.out; fail "systemd-analyze verify refused onv-provider.service"; }
if grep -q 'onv-provider.service' /tmp/verify.out; then
    cat /tmp/verify.out
    fail "systemd-analyze verify has something to say about onv-provider.service"
fi
ok "systemd-analyze verify loads onv-provider.service with nothing to say"
echo "logs: every case passed"
