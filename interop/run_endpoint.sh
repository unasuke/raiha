#!/bin/sh
#
# Thin wrapper invoked by quic-interop-runner. The runner sets every
# bit of state via environment variables (ROLE, TESTCASE_*,
# WAITFORSERVER, WWW, DOWNLOADS, CERTS, QLOGDIR, SSLKEYLOGFILE), so
# all this script has to do is hand control to the Ruby entry point
# and propagate its exit status.
#
# In the sim-less compose layout (interop/quic-interop-runner.no-sim.yml)
# we capture pcap on eth0 here, since the no-op alpine sim cannot
# observe traffic between client and server. The Dockerfile sets
# `cap_net_raw,cap_net_admin+eip` on /usr/bin/tcpdump so we can run
# tcpdump as the existing root user without auto-dropping privileges
# to the "tcpdump" account — the cross-user-namespace signal that
# rootless podman blocks then never has to happen.
set -eu

mkdir -p /logs
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
  # abruptly during container teardown.
  tcpdump -Z root -i eth0 -U -w "$PCAP" -s 0 udp >/dev/null 2>&1 &
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
