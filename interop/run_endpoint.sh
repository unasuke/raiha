#!/bin/sh
#
# Thin wrapper invoked by quic-interop-runner. The runner sets every
# bit of state via environment variables (ROLE, TESTCASE_*,
# WAITFORSERVER, WWW, DOWNLOADS, CERTS, QLOGDIR, SSLKEYLOGFILE), so
# all this script has to do is hand control to the Ruby entry point
# and propagate its exit status.
set -eu

exec raiha-interop "$@"
