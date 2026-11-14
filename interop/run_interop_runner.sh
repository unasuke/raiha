#!/usr/bin/env bash
#
# Runs quic-interop-runner on the sim-less compose
# (interop/quic-interop-runner.no-sim.yml) with its network made afresh.
#
# The runner brings the compose up again and again but never takes it
# down, so its containers and network outlive it. The compose pins its
# network to 193.167.0.0/16, as trace.py fixes the addresses of the
# client and the server; the network another run left there, of this
# checkout or another, of the sim-less compose or the one with the
# simulator, is in the way of the next run's. So before the run, the
# networks on 193.167.x.x go, with the stopped containers on them and
# those of the names the compose gives (sim, client, server), and after
# it, those of this run go the same way. A container still running is
# left alone, and the run does not start.
#
# Usage, from anywhere:
#   interop/run_interop_runner.sh <arguments of run.py>
# RUNNER_DIR is the clone of quic-interop-runner (tmp/quic-interop-runner
# by default) and PYTHON the command that runs Python there (python by
# default).
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
runner=${RUNNER_DIR:-$repo/tmp/quic-interop-runner}
read -r -a python <<< "${PYTHON:-python}"
compose=docker-compose.no-sim.yml

# Removes the stopped container `$1`; fails when it is running.
remove_stopped() {
  local state
  state=$(docker inspect --format '{{.State.Status}}' "$1" 2>/dev/null) || return 0
  if [ "$state" = running ]; then
    echo "container $1 is running: another run is going on" >&2
    return 1
  fi
  docker rm "$1" >/dev/null
}

# Removes the networks on 193.167.x.x and the containers of the compose's
# names, with the containers on those networks.
clear_addresses() {
  local info network name
  for name in sim client server; do
    remove_stopped "$name"
  done
  for network in $(docker network ls --format '{{.Name}}'); do
    info=$(docker network inspect "$network")
    grep -qE '"[Ss]ubnet": *"193\.167\.' <<< "$info" || continue
    for name in $(docker ps -a --filter "network=$network" --format '{{.Names}}'); do
      remove_stopped "$name"
    done
    docker network rm "$network" >/dev/null
  done
}

cp "$repo/interop/quic-interop-runner.no-sim.yml" "$runner/$compose"
cd "$runner"
clear_addresses
trap 'clear_addresses || true' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
COMPOSE_FILE=$compose "${python[@]}" run.py "$@"
