# frozen_string_literal: true

# The namespace skeleton for the next release of raiha. This is the only
# file written in the nested form; every other file opens its module in the
# compact form (`module Raiha::Next::TLS`), so a bare `TLS` or `QUIC` raises
# NameError instead of resolving to the old implementation or a neighbouring
# layer.
#
# Only `Raiha` and `Raiha::Next` are defined here. Defining the layer modules
# too would make `Raiha::Next::QUIC` visible after `require "raiha/next/tls"`.
module Raiha
  module Next
  end
end
