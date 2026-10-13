# The next release of raiha (lib/raiha/next). It reads none of the old
# implementation's RBS, so the old RBS cannot break it and the new code
# cannot refer to old types.
# `sig/raiha.rbs` is here for `Raiha::VERSION`.
#
# Steep gives each file to the first target that matches it, so this target
# must come before :lib, whose `check "lib"` would otherwise take
# lib/raiha/next as well.
target :next do
  signature "sig/raiha/next", "sig/raiha.rbs", "sig/patches/io_buffer.rbs", "sig/patches/openssl.rbs", "sig/next_patches"
  check "lib/raiha/next"
  library "ipaddr"
  library "securerandom"
end

target :lib do
  # Its signatures stay out of :next, which steep would otherwise load them
  # into as well.
  unreferenced!
  signature "sig"
  check "lib"
  library "openssl"
  library "securerandom"
  library "stringio"
  library "socket"
  library "logger"
  library "forwardable"
end
