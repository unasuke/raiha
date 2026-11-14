#!/bin/sh
#
# Thin wrapper invoked by quic-interop-runner. The runner sets every
# bit of state via environment variables (ROLE, TESTCASE_*,
# WAITFORSERVER, WWW, DOWNLOADS, CERTS, QLOGDIR, SSLKEYLOGFILE), so
# all this script has to do is hand control to the Ruby entry point
# and propagate its exit status.
#
# With the ns-3 simulator, quic-interop-runner's own compose, the
# datagrams to the other side go through the simulator, .2 of each
# network, as the endpoint image of quic-network-simulator sets up in its
# setup.sh: the routes to 193.167.0.0/16 and fd00:cafe:cafe::/48 go
# through it, the direct ones of the endpoint's own network go, and the
# checksums are computed here, with the offload off, as the simulator
# passes on only datagrams whose checksums are valid. The client waits
# for the simulator to listen on port 57832 first.
#
# In the sim-less compose layout (interop/quic-interop-runner.no-sim.yml,
# which sets NETWORK_SIMULATOR=none) we capture pcap on eth0 here, since
# the no-op alpine sim cannot observe traffic between client and server.
# The Dockerfile sets `cap_net_raw,cap_net_admin+eip` on /usr/bin/tcpdump
# so we can run tcpdump as the existing root user without auto-dropping
# privileges to the "tcpdump" account — the cross-user-namespace signal
# that rootless podman blocks then never has to happen.
set -eu

mkdir -p /logs

if [ "${NETWORK_SIMULATOR:-ns3}" != none ]; then
  ethtool -K eth0 tx off >/dev/null
  # The IPv4 address comes first, and the IPv6 one, when there is one,
  # second.
  ip4=$(hostname -I | cut -d " " -f 1)
  ip6=$(hostname -I | cut -s -d " " -f 2)
  ip route add 193.167.0.0/16 via "${ip4%.*}.2"
  ip route del "${ip4%.*}.0/24"
  case "$ip6" in
    *:*)
      ip -6 route add fd00:cafe:cafe::/48 via "${ip6%:*}:2"
      ip -6 route del "${ip6%:*}:/64"
      ;;
  esac
  if [ "${ROLE:-}" = client ]; then
    ruby -rsocket -e '
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30
      begin
        Socket.tcp("sim", 57832, connect_timeout: 1).close
      rescue SystemCallError, SocketError
        raise if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
        sleep 0.2
        retry
      end'
  fi
  exec raiha-interop "$@"
fi

case "${ROLE:-}" in
  client) PCAP=/logs/trace_node_left.pcap ;;
  server) PCAP=/logs/trace_node_right.pcap ;;
  *)      PCAP=/logs/trace.pcap ;;
esac

TCPDUMP_PID=""
if command -v tcpdump >/dev/null 2>&1; then
  # -Z root keeps tcpdump as the container's uid 0 instead of
  # auto-dropping to user "tcpdump" — without -Z the dropped
  # process can't actually pull packets off eth0 in this rootless
  # podman setup and the resulting pcap stays at 24 bytes (header
  # only). With -U each captured packet is flushed to disk
  # immediately so the pcap survives even when tcpdump is reaped
  # abruptly during container teardown. --immediate-mode hands each
  # packet to tcpdump as it comes; without it the kernel holds them
  # for up to a second, and a client that is done sooner, as in
  # handshake or resumption, left a pcap of the header alone.
  tcpdump -Z root -i eth0 --immediate-mode -U -w "$PCAP" -s 0 udp >/dev/null 2>&1 &
  TCPDUMP_PID=$!
  sleep 0.3
fi

raiha-interop "$@"
status=$?

if [ -n "$TCPDUMP_PID" ]; then
  # Try to nudge tcpdump into a clean shutdown so libpcap finalises
  # the file. Under rootless podman this kill is rejected with
  # EPERM (the user namespace blocks signalling a setuid'd peer
  # even at uid 0) — fall back to letting docker stop's SIGKILL
  # take it down a few seconds later. -U flushes per packet, but
  # we also wait briefly so any packets still in tcpdump's ring
  # buffer get drained before the kernel reaps the process.
  kill -TERM "$TCPDUMP_PID" 2>/dev/null || true
  sleep 1
fi

exit "$status"
