#!/usr/bin/env bash
# The provider opening, hermetically: run inside a disposable privileged
# container by nft_test.sh, never on a host. The container's own network
# namespace plays the provider host; four namespaces inside it play the
# internet, the provider's LAN, and two buyer machines on the egress bridge.
#
#   wan    203.0.113.50   on vmbr0, the host's uplink   (host: 203.0.113.1)
#   lan    192.168.100.50 on vmbr0 too, the LAN         (host: 192.168.100.78)
#   guest  10.201.0.105   on onvnat0, opened on 31820   (host: 10.201.0.1)
#   other  10.201.0.106   on onvnat0, holds 31821 but not yet seen
#
# Loaded: the egress policy omnuv's play installs (/t/egress.nft), a SNAT of
# the bridge's subnet as Proxmox's SDN writes it, and the agent's table, by
# the packaged binary's own `apply-opening`. Every verdict is a packet sent
# and an answer heard or not heard.
set -uo pipefail
cd /t || exit 1
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1"; fails=$((fails + 1)); }
expect() { # name want got   (want is a glob)
    # shellcheck disable=SC2053
    if [[ "$3" == $2 ]]; then ok "$1"; else bad "$1: wanted [$2], got [$3]"; fi
}
nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

# ---- the host, its uplink and LAN on one bridge, the egress bridge ----
echo 1 > /proc/sys/net/ipv4/ip_forward
ip link add vmbr0 type bridge && ip link set vmbr0 up
ip addr add 203.0.113.1/24 dev vmbr0
ip addr add 192.168.100.78/24 dev vmbr0
ip link add onvnat0 type bridge && ip link set onvnat0 up
ip addr add 10.201.0.1/24 dev onvnat0
peer() { # ns bridge address gateway-or-route...
    local ns=$1 br=$2 addr=$3; shift 3
    ip netns add "$ns"
    ip link add "p-$ns" type veth peer name eth0 netns "$ns"
    ip link set "p-$ns" master "$br" up
    nsx "$ns" ip link set lo up
    nsx "$ns" ip link set eth0 up
    nsx "$ns" ip addr add "$addr" dev eth0
    while [ $# -gt 0 ]; do nsx "$ns" ip route add "$1" via "$2"; shift 2; done
}
peer wan vmbr0 203.0.113.50/24 10.201.0.0/24 203.0.113.1
peer lan vmbr0 192.168.100.50/24 10.201.0.0/24 192.168.100.78 203.0.113.0/24 192.168.100.78
peer guest onvnat0 10.201.0.105/24 default 10.201.0.1
peer other onvnat0 10.201.0.106/24 default 10.201.0.1

# Proxmox SDN's SNAT for the egress subnet (`--snat 1`), at the priority
# iptables' nat table holds: the opening's own masquerade runs ahead of it.
# fully-random, which Proxmox's is not: so a source port that survives is
# the opening's doing and nothing else's (the control below shows one that
# does not).
nft -f - <<'NFT'
table ip pvelike {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 10.201.0.0/24 oifname "vmbr0" snat ip to 203.0.113.1 fully-random
    }
}
NFT
nft -f /t/egress.nft || { echo "FAIL  the egress policy did not load"; exit 1; }

# ---- the agent's files ----
mkdir -p /etc/onv /var/lib/onv/snippets
config() { # enabled reach public ports
    cat > /etc/onv/agent.yaml <<YAML
core:
  url: https://core.invalid
proxmox:
  apiUrl: https://127.0.0.1:8006
  tokenId: onv@pve!agent
  snippetDir: /var/lib/onv/snippets
opening:
  enabled: $1
  reach: $2
  publicAddress: $3
  interface: "vmbr0"
  ports: "$4"
YAML
}
book() { # json of machines
    printf '{"machines": %s}\n' "$1" > /var/lib/onv/opening.json
}
apply() { onv-provider apply-opening --config /etc/onv/agent.yaml > /tmp/apply.out 2>&1; echo $?; }
table() { nft list table inet onv_opening 2>/dev/null; }
has_table() { if table > /dev/null; then echo present; else echo absent; fi; }

# ---- listeners: the guest answers on its port, on the next one, and on TCP ----
# Backgrounded as `ip netns exec` itself, never through nsx: a function run
# in the background is a subshell, and its $! is not the listener's pid.
ip netns exec guest python3 /t/udp.py echo 31820 /tmp/guest.heard & echo_pid=$!
nsx guest python3 /t/udp.py echo 31821 &
nsx guest python3 /t/udp.py tcp 31820 &
nsx other python3 /t/udp.py echo 31821 &
for _ in $(seq 1 50); do
    [ "$(nsx guest ss -lun | grep -c ':3182[01] ')" = 2 ] && [ "$(nsx other ss -lun | grep -c ':31821 ')" = 1 ] && break
    sleep 0.1 # wait: listeners binding in their namespaces, polled
done

ask() { nsx "$1" python3 /t/udp.py ask "${@:2}"; }

# ---- on ----
config true public 203.0.113.1 31820-31822
book '{"m-guest": {"port": 31820, "address": "10.201.0.105"}, "m-other": {"port": 31821, "address": null}}'
expect "on: apply-opening exits 0" 0 "$(apply)"
expect "on: one rule pair, for the machine seen on the bridge" "1 1" \
    "$(table | grep -c ' dnat ip to 10.201.0.105:31820') $(table | grep -c 'masquerade to :31820')"
expect "the internet reaches the guest's own port, answered from the public address and port" \
    "answer 203.0.113.1:31820 echo probe" "$(ask wan 203.0.113.1 31820)"
expect "a port held by a machine not yet seen reaches nothing" "silence" "$(ask wan 203.0.113.1 31821)"
expect "a port outside the book reaches nothing" "silence" "$(ask wan 203.0.113.1 31822)"
expect "TCP on the guest's port does not reach it" "refused" "$(nsx wan python3 /t/udp.py connect 203.0.113.1 31820)"
expect "the guest's own address is not reachable from the internet" "silence" "$(ask wan 10.201.0.105 31820)"
expect "the LAN is not translated, by the LAN address" "silence" "$(ask lan 192.168.100.78 31820)"
expect "the LAN is not translated, by the public address" "silence" "$(ask lan 203.0.113.1 31820)"
expect "the LAN cannot reach the guest directly" "silence" "$(ask lan 10.201.0.105 31820)"
# Silence above could be the guest's answer being dropped on its way back;
# what the guest itself heard says whether anything from the LAN arrived.
expect "the guest heard the internet and nothing from the LAN" "203.0.113.50" \
    "$(cut -d: -f1 /tmp/guest.heard | sort -u | tr '\n' ' ' | sed 's/ $//')"

bound() { # ns port: poll until something listens there
    for _ in $(seq 1 50); do nsx "$1" ss -lun | grep -q ":$2 " && return 0; sleep 0.1; done # wait: binding, polled
    return 1
}

# The guest cannot reach the LAN: a listener there hears the host (the
# control: it is listening) and nothing from the guest.
ip netns exec lan python3 /t/udp.py hear 5000 3 > /tmp/lan.heard & hear_pid=$!
bound lan 5000
ask guest 192.168.100.50 5000 > /dev/null
python3 /t/udp.py ask 192.168.100.50 5000 > /dev/null
wait "$hear_pid"
expect "the LAN listener heard the host, the control, and nothing from the guest" "1 heard 192.168.100.78:* probe" "$(grep -c . /tmp/lan.heard) $(cat /tmp/lan.heard)"

# What the guest sends from its port leaves from the public address and the
# same port, so the router's forward of that port matches it.
kill "$echo_pid"; wait "$echo_pid" 2>/dev/null
ip netns exec wan python3 /t/udp.py hear 40000 3 > /tmp/wan.heard & hear_pid=$!
bound wan 40000
ask guest 203.0.113.50 40000 31820 > /dev/null
ask guest 203.0.113.50 40000 31899 > /dev/null
wait "$hear_pid"
expect "the guest's port leaves as the public port" "heard 203.0.113.1:31820 probe*" "$(sed -n 1p /tmp/wan.heard)"
expect "a port it was not given does not (control)" "heard 203.0.113.1:* probe" "$(sed -n 2p /tmp/wan.heard | grep -v ':31899 ')"
ip netns exec guest python3 /t/udp.py echo 31820 /tmp/guest.heard & echo_pid=$!
bound guest 31820

# Idempotent: applied again, the kernel holds the same rules.
before="$(table)"
expect "applied twice: exit 0" 0 "$(apply)"
expect "applied twice: the same table" "$before" "$(table)"

# The proof can fail: without onv_egress's `ct status dnat` accept, the
# opening's translated flow is the `ct state new` the bridge drops.
grep -v 'ct status dnat accept' /t/egress.nft > /tmp/egress-without.nft
nft delete table inet onv_egress && nft -f /tmp/egress-without.nft
expect "without the egress accept, the internet does not reach the guest" "silence" "$(ask wan 203.0.113.1 31820)"
nft delete table inet onv_egress && nft -f /t/egress.nft
expect "with it back, it does again" "answer 203.0.113.1:31820 echo probe" "$(ask wan 203.0.113.1 31820)"

# ---- refusals: each ends with no table ----
book '{"m-guest": {"port": 80, "address": "10.201.0.105"}}'
expect "a port outside the range: exit 1" 1 "$(apply)"
expect "a port outside the range: no table" absent "$(has_table)"
book '{"m-guest": {"port": 31820, "address": "192.168.100.50"}}'
apply > /dev/null
expect "an address on the LAN: no table" absent "$(has_table)"
book '{"m-guest": {"port": 31820, "address": "10.201.0.105"}}'
expect "back to a good book: exit 0" 0 "$(apply)"
config true public 198.51.100.9 31820-31822
expect "reach public, address not on the host: exit 1" 1 "$(apply)"
expect "reach public, address not on the host: no table" absent "$(has_table)"
config true null 203.0.113.1 31820-31822
expect "on with no reach: exit 2" 2 "$(apply)"
expect "on with no reach: no table" absent "$(has_table)"
config true forwarded 203.0.113.1 31820-31822
expect "reach forwarded: exit 0" 0 "$(apply)"
expect "reach forwarded: the table" present "$(has_table)"

# ---- off: every rule gone, nothing reaches the guest ----
config false null null 31820-31970
expect "off: exit 0" 0 "$(apply)"
expect "off: no table" absent "$(has_table)"
expect "off: the internet does not reach the guest" "silence" "$(ask wan 203.0.113.1 31820)"
expect "off again: exit 0" 0 "$(apply)"
cat /tmp/apply.out

echo
if [ "$fails" -eq 0 ]; then echo "opening: every case passed"; else echo "opening: $fails case(s) FAILED"; fi
[ "$fails" -eq 0 ]
