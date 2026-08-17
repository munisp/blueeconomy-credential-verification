#!/usr/bin/env bash
# LOCAL TEST ONLY. This script refuses host networking and requires explicit authorization.
set -euo pipefail
: "${S4_NETWORK_FAULT_TEST_ENABLED:?set true for a local test window}"
: "${S4_NETWORK_FAULT_AUTHORIZATION_REF:?supply approved local test reference}"
: "${S4_FAULT_TARGET_CONTAINER:?supply isolated Docker test container name or ID}"
: "${S4_VERIFIER_TEST_COMMAND:?supply the local verifier test command}"
: "${S4_NETEM_DELAY_MS:=250}"
: "${S4_NETEM_JITTER_MS:=50}"
: "${S4_NETEM_LOSS_PERCENT:=5}"
[[ "$S4_NETWORK_FAULT_TEST_ENABLED" == true ]] || { echo 'S4 network fault test is not enabled' >&2; exit 2; }
[[ "$S4_NETEM_DELAY_MS" =~ ^[0-9]+$ && "$S4_NETEM_JITTER_MS" =~ ^[0-9]+$ && "$S4_NETEM_LOSS_PERCENT" =~ ^([0-9]|[1-9][0-9]|100)$ ]] || { echo 'invalid netem values' >&2; exit 2; }
docker inspect "$S4_FAULT_TARGET_CONTAINER" >/dev/null
pid=$(docker inspect -f '{{.State.Pid}}' "$S4_FAULT_TARGET_CONTAINER")
[[ "$pid" =~ ^[1-9][0-9]*$ ]] || { echo 'target container is not running' >&2; exit 2; }
cleanup() { docker run --rm --privileged --pid="container:$S4_FAULT_TARGET_CONTAINER" alpine:3.20 tc qdisc del dev eth0 root netem >/dev/null 2>&1 || true; }
trap cleanup EXIT
echo "S4_LOCAL_NETWORK_FAULT authorization=$S4_NETWORK_FAULT_AUTHORIZATION_REF target=$S4_FAULT_TARGET_CONTAINER delay=${S4_NETEM_DELAY_MS}ms jitter=${S4_NETEM_JITTER_MS}ms loss=${S4_NETEM_LOSS_PERCENT}%"
docker run --rm --privileged --pid="container:$S4_FAULT_TARGET_CONTAINER" alpine:3.20 tc qdisc replace dev eth0 root netem delay "${S4_NETEM_DELAY_MS}ms" "${S4_NETEM_JITTER_MS}ms" loss "${S4_NETEM_LOSS_PERCENT}%"
bash -lc "$S4_VERIFIER_TEST_COMMAND"
echo 'S4_LOCAL_NETWORK_FAULT_TEST_PASSED'
