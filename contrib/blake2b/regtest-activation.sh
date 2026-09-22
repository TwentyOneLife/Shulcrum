#!/usr/bin/env bash
#
# Runs a regtest chain across its BLAKE2b activation height and checks what this server serves
# either side of it, and to whom. That is the one thing a unit test cannot show: a chain crosses
# its activation height while clients are connected, and a client that negotiated an older protocol
# beforehand must be dropped rather than sent a header it would misread.
#
# Usage:
#   contrib/blake2b/regtest-activation.sh
#
# Environment:
#   BITCOIND     how to run a BLAKE2b-capable bitcoind      (default: bitcoind)
#   BITCOIN_CLI  how to run its cli                         (default: bitcoin-cli)
#   SHULCRUM     how to run this server                     (default: ./Fulcrum)
#   ACTIVATION   the height to activate BLAKE2b at          (default: 20)
#   KEEP         set to 1 to keep the working directory
#
# Each may be a command rather than a path, so the server can be run from a container:
#   SHULCRUM="docker run --rm --network host -v $PWD/build:/b:ro image /b/Fulcrum" ...
#
set -euo pipefail

BITCOIND=${BITCOIND:-bitcoind}
BITCOIN_CLI=${BITCOIN_CLI:-bitcoin-cli}
SHULCRUM=${SHULCRUM:-./Fulcrum}
ACTIVATION=${ACTIVATION:-20}
WORK=$(mktemp -d)
NODE_PORT=18443
TCP_PORT=51001

cleanup() {
    set +e
    [ -n "${SHULCRUM_PID:-}" ] && kill "$SHULCRUM_PID" 2>/dev/null
    $BITCOIN_CLI -regtest -datadir="$WORK/node" -rpcport=$NODE_PORT stop >/dev/null 2>&1
    wait 2>/dev/null
    if [ "${KEEP:-0}" = 1 ]; then echo "working directory kept at $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

mkdir -p "$WORK/node" "$WORK/index"

echo "== starting a regtest node, BLAKE2b activating at height $ACTIVATION"
$BITCOIND -regtest -datadir="$WORK/node" -rpcport=$NODE_PORT -port=$((NODE_PORT+1)) \
          -testactivationheight=blake2b@"$ACTIVATION" -txindex=1 -daemon -fallbackfee=0.0002 >/dev/null
CLI="$BITCOIN_CLI -regtest -datadir=$WORK/node -rpcport=$NODE_PORT"
for _ in $(seq 60); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$CLI createwallet probe >/dev/null
ADDR=$($CLI getnewaddress)

# Below the activation height the chain is ordinary, which is the state the server must not change.
$CLI generatetoaddress $((ACTIVATION - 5)) "$ADDR" >/dev/null
echo "   mined to height $($CLI getblockcount)"

cat > "$WORK/shulcrum.conf" <<CONF
datadir = $WORK/index
bitcoind = 127.0.0.1:$NODE_PORT
rpccookie = $WORK/node/regtest/.cookie
extended_headers = true
tcp = 127.0.0.1:$TCP_PORT
peering = false
announce = false
db_mem = 256
CONF

echo "== starting the server"
$SHULCRUM "$WORK/shulcrum.conf" > "$WORK/shulcrum.log" 2>&1 &
SHULCRUM_PID=$!
for _ in $(seq 120); do
    (exec 3<>/dev/tcp/127.0.0.1/$TCP_PORT) 2>/dev/null && break
    sleep 1
done

echo "== driving a session across the activation height"
SHULCRUM_TCP_PORT=$TCP_PORT BITCOIN_CLI="$CLI" ACTIVATION_HEIGHT=$ACTIVATION \
    python3 "$(dirname "$0")/electrum_probe.py"
