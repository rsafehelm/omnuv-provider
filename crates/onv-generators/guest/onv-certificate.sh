#!/bin/bash
# onv-certificate: this machine fetches its project's web certificate from
# Core (omnuv's docs/plans/private-names-https.md, D-2: pulled by the machine).
#
# Run by onv-certificate.timer, as root, a few minutes apart. Each run:
#
#   1. holds a token of its own, or trades the bootstrap first boot wrote
#      (pull.env) for one at Core: POST /v1/machine/certificate/exchange
#   2. asks Core for the project's certificate, naming the one it holds:
#      GET /v1/machine/certificate?have=<fingerprint>
#      204  unchanged            404  none issued yet: asked again next run
#      200  a new one            401  the token is not a live machine's
#   3. checks a new one before it is used: it parses, has not ended, its key
#      is its own, and its fingerprint is the one Core named
#   4. puts it in place, the key readable by root alone, and runs each hook
#      in hooks.d, so a recipe's TLS front can reload
#
# A credential never reaches a command line, where any process on the machine
# could read it: curl reads its Authorization header from a file of mode 0600.
# Nothing here prints a token or a key.
set -euo pipefail
umask 077

CONF="${ONV_CERT_CONF:-/etc/onv/certificate/pull.env}"
STATE="${ONV_CERT_STATE:-/var/lib/onv/certificate}"
LIVE="${ONV_CERT_LIVE:-/etc/onv/certificate/live}"
HOOKS="${ONV_CERT_HOOKS:-/etc/onv/certificate/hooks.d}"
# A test's own authority; on a machine, the system's roots.
CACERT="${ONV_CERT_CACERT:-}"

say() { echo "onv-certificate: $*"; }
fail() { echo "onv-certificate: $*" >&2; exit 1; }

[ -r "$CONF" ] || { say "no $CONF: this machine fetches no certificate"; exit 0; }

# KEY=VALUE, read rather than sourced: the file is data.
core_url=""
bootstrap=""
while IFS='=' read -r key value; do
    case "$key" in
        ONV_CORE_URL) core_url="$value" ;;
        ONV_BOOTSTRAP) bootstrap="$value" ;;
    esac
done < "$CONF"
case "$core_url" in
    https://*) ;;
    *) fail "ONV_CORE_URL in $CONF is not an https:// origin" ;;
esac
core_url="${core_url%/}"

mkdir -p "$STATE" "$LIVE"
chmod 700 "$STATE" "$LIVE"
work="$(mktemp -d "$STATE/run.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# curl, over TLS only, with the credential in a header file. $1 the bearer,
# then curl's own arguments. Prints the HTTP status; the body is in $work/body.
ask() {
    local bearer="$1"
    shift
    printf 'Authorization: Bearer %s\n' "$bearer" > "$work/header"
    local tls=() code
    if [ -n "$CACERT" ]; then tls=(--cacert "$CACERT"); fi
    rm -f "$work/body"
    # A transport failure prints 000 itself and exits non-zero; either way
    # the status is the answer, and the caller decides.
    code="$(curl -sS --proto '=https' --max-time 30 "${tls[@]}" -H "@$work/header" \
        -o "$work/body" -w '%{http_code}' "$@")" || true
    rm -f "$work/header"
    echo "${code:-000}"
}

# A JSON field of the last answer, or nothing.
field() {
    python3 -c 'import json, sys
try:
    v = json.load(open(sys.argv[1])).get(sys.argv[2])
except Exception:
    v = None
sys.stdout.write(v if isinstance(v, str) else "")' "$work/body" "$1"
}

exchange() {
    [ -n "$bootstrap" ] || fail "no token and no bootstrap in $CONF"
    local status
    status="$(ask "$bootstrap" -X POST "$core_url/v1/machine/certificate/exchange")"
    case "$status" in
        200) ;;
        401) fail "Core refused this machine's bootstrap: spent, revoked, or the machine is deleted" ;;
        404) say "Core serves no certificates (switched off)"; exit 0 ;;
        *) fail "the exchange answered $status" ;;
    esac
    local token
    token="$(field token)"
    [ -n "$token" ] || fail "the exchange answered no token"
    printf '%s\n' "$token" > "$STATE/token.new"
    mv -f "$STATE/token.new" "$STATE/token"
    say "traded the bootstrap for a token of this machine's own"
}

traded=0
if [ ! -s "$STATE/token" ]; then
    exchange
    traded=1
fi

have=""
[ -s "$LIVE/fingerprint" ] && have="$(cat "$LIVE/fingerprint")"
fetch() {
    local token
    token="$(cat "$STATE/token")"
    ask "$token" -G "$core_url/v1/machine/certificate" --data-urlencode "have=$have"
}
status="$(fetch)"
if [ "$status" = 401 ] && [ "$traded" = 0 ]; then
    # A token Core no longer knows: the machine was placed again, or the
    # answer to an earlier trade was lost. The bootstrap trades again until a
    # token has fetched once.
    say "Core refused the held token; trading the bootstrap again"
    rm -f "$STATE/token"
    exchange
    status="$(fetch)"
fi
case "$status" in
    204) say "the certificate held is current"; exit 0 ;;
    404)
        if [ "$(field code)" = certificate_not_issued ]; then
            say "no certificate issued for this project yet; asking again next run"
            exit 0
        fi
        say "Core serves no certificates (switched off)"
        exit 0
        ;;
    200) ;;
    401) fail "Core refused this machine's token: it was revoked, or the machine is deleted" ;;
    *) fail "the fetch answered $status" ;;
esac

python3 -c 'import json, sys
d = json.load(open(sys.argv[1]))
for k in ("chain_pem", "key_pem", "fingerprint"):
    if not isinstance(d.get(k), str) or not d[k]:
        sys.exit("the answer has no " + k)
open(sys.argv[2], "w").write(d["chain_pem"])
open(sys.argv[3], "w").write(d["key_pem"])
open(sys.argv[4], "w").write(d["fingerprint"].strip().lower() + "\n")' \
    "$work/body" "$work/fullchain.pem" "$work/privkey.pem" "$work/fingerprint" \
    || fail "the answer did not hold a certificate"
rm -f "$work/body"

# Checked before anything is replaced: a certificate that fails here leaves
# the one in place serving.
openssl x509 -in "$work/fullchain.pem" -noout -checkend 0 > /dev/null \
    || fail "the certificate Core gave has ended or does not parse"
cert_pub="$(openssl x509 -in "$work/fullchain.pem" -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum)"
key_pub="$(openssl pkey -in "$work/privkey.pem" -pubout -outform DER | sha256sum)"
[ "$cert_pub" = "$key_pub" ] || fail "the key Core gave is not the certificate's"
der_fp="$(openssl x509 -in "$work/fullchain.pem" -outform DER | sha256sum | cut -d' ' -f1)"
[ "$der_fp" = "$(cat "$work/fingerprint")" ] || fail "the certificate is not the one Core named"

# The key and the chain first, then the hooks, and the fingerprint last, only
# once every hook ran: a run stopped part-way, or a hook that failed, leaves
# the old fingerprint, so the next run fetches again and runs them again.
chmod 600 "$work/privkey.pem"
chmod 644 "$work/fullchain.pem" "$work/fingerprint"
mv -f "$work/privkey.pem" "$LIVE/privkey.pem"
mv -f "$work/fullchain.pem" "$LIVE/fullchain.pem"
say "installed the project's certificate $der_fp"

hooks_failed=0
if [ -d "$HOOKS" ]; then
    for hook in "$HOOKS"/*; do
        [ -x "$hook" ] || continue
        if "$hook"; then
            say "hook $(basename "$hook") ran"
        else
            echo "onv-certificate: hook $(basename "$hook") failed; it runs again next time" >&2
            hooks_failed=1
        fi
    done
fi
[ "$hooks_failed" = 0 ] || exit 1
mv -f "$work/fingerprint" "$LIVE/fingerprint"
