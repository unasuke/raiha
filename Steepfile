# The next release of raiha (lib/raiha/next). It reads none of the old
# implementation's RBS, so the old RBS cannot break it and the new code
# cannot refer to old types.
# `sig/raiha.rbs` is here for `Raiha::VERSION`.
#
# Steep gives each file to the first target that matches it, so this target
# must come before :lib, whose `check "lib"` would otherwise take
# lib/raiha/next as well.
target :next do
  signature "sig/raiha/next", "sig/raiha.rbs", "sig/patches"
  check "lib/raiha/next"
end

target :lib do
  signature "sig"
  check "lib"
  library "openssl"
  library "securerandom"
  library "stringio"
  library "socket"
  library "logger"
  library "forwardable"
end
