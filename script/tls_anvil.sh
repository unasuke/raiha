#!/bin/bash
# TLS-Anvil (https://github.com/tls-attacker/TLS-Anvil) against the TLS of
# raiha over TCP, in docker on the host's network, of
# the version pinned here. `server` tests script/fuzzing_server.rb, and
# `client` script/tls_anvil_client.rb, which TLS-Anvil triggers before
# each handshake. The results go to tmp/tls-anvil/<mode>; at strength 1
# the server tests take about twenty minutes and the client ones ten.
#
# Usage:
#   script/tls_anvil.sh server|client [strength]   (1 by default)
set -eu

MODE="${1:?usage: tls_anvil.sh server|client [strength]}"
STRENGTH="${2:-1}"
IMAGE=ghcr.io/tls-attacker/tlsanvil:v1.5.3
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="${PROJECT_DIR}/tmp/tls-anvil/${MODE}"
SERVER_PORT=4466
TRIGGER_PORT=4477
ANVIL_PORT=4478

rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"

case "$MODE" in
server)
  (cd "$PROJECT_DIR" && exec bundle exec ruby "${SCRIPT_DIR}/fuzzing_server.rb" "$SERVER_PORT") 2> "${OUTPUT}/peer.log" &
  ARGS=(server -connect "localhost:${SERVER_PORT}")
  ;;
client)
  (cd "$PROJECT_DIR" && exec bundle exec ruby "${SCRIPT_DIR}/tls_anvil_client.rb" "$TRIGGER_PORT" "$ANVIL_PORT") 2> "${OUTPUT}/peer.log" &
  ARGS=(client -port "$ANVIL_PORT" -triggerScript curl -s "http://127.0.0.1:${TRIGGER_PORT}/")
  ;;
*)
  echo "unknown mode: $MODE" >&2
  exit 1
  ;;
esac
PEER_PID=$!
trap 'kill "$PEER_PID" 2>/dev/null || true; wait "$PEER_PID" 2>/dev/null || true' EXIT
sleep 3

docker run --rm --network host -v "${OUTPUT}:/output" "$IMAGE" \
  -outputFolder /output -parallelHandshakes 1 -strength "$STRENGTH" -identifier "raiha-${MODE}" -prettyPrintJSON "${ARGS[@]}"
