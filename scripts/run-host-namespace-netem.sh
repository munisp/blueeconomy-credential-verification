#!/usr/bin/env bash
# LOCAL DISPOSABLE HOST ONLY: never targets the host default namespace or external endpoints.
set -euo pipefail
: "${S4_NS_AUTH_REF:?local fault-test authorization reference required}"
: "${S4_NS_VERIFIER_COMMAND:?approved local verifier command required}"
: "${S4_NS_AUTHORITY_COMMAND:?approved local fixture authority command required}"
: "${S4_NS_DELAY_MS:=250}"
: "${S4_NS_JITTER_MS:=50}"
: "${S4_NS_LOSS_PERCENT:=5}"
[[ "$S4_NS_DELAY_MS" =~ ^[0-9]{1,3}$ && "$S4_NS_JITTER_MS" =~ ^[0-9]{1,3}$ && "$S4_NS_LOSS_PERCENT" =~ ^([0-9]|10)$ ]] || { echo 'netem bounds exceed local policy' >&2; exit 2; }
[[ $(id -u) == 0 ]] || { echo 'run under an approved root/CAP_NET_ADMIN local test account' >&2; exit 2; }
client=s4-client-$RANDOM; authority=s4-authority-$RANDOM
cleanup() { ip netns del "$client" 2>/dev/null || true; ip netns del "$authority" 2>/dev/null || true; }
trap cleanup EXIT
ip netns add "$client"; ip netns add "$authority"
ip link add veth-client type veth peer name veth-authority
ip link set veth-client netns "$client"; ip link set veth-authority netns "$authority"
ip -n "$client" addr add 10.200.10.2/30 dev veth-client; ip -n "$authority" addr add 10.200.10.1/30 dev veth-authority
ip -n "$client" link set lo up; ip -n "$authority" link set lo up; ip -n "$client" link set veth-client up; ip -n "$authority" link set veth-authority up
printf 'S4_HOST_NAMESPACE_NETEM authorization=%s client=%s authority=%s delay=%sms jitter=%sms loss=%s%%\n' "$S4_NS_AUTH_REF" "$client" "$authority" "$S4_NS_DELAY_MS" "$S4_NS_JITTER_MS" "$S4_NS_LOSS_PERCENT"
ip netns exec "$authority" sh -lc "$S4_NS_AUTHORITY_COMMAND" & authority_pid=$!
sleep 1
ip netns exec "$client" ping -c 1 -W 1 10.200.10.1 >/dev/null
ip netns exec "$client" tc qdisc replace dev veth-client root netem delay "${S4_NS_DELAY_MS}ms" "${S4_NS_JITTER_MS}ms" loss "${S4_NS_LOSS_PERCENT}%"
ip netns exec "$client" sh -lc "$S4_NS_VERIFIER_COMMAND"
ip netns exec "$client" tc qdisc del dev veth-client root netem
kill "$authority_pid" 2>/dev/null || true
printf '%s\n' 'S4_HOST_NAMESPACE_NETEM_TEST_PASSED'
