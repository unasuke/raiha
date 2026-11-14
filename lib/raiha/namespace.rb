# frozen_string_literal: true

# The namespace skeleton of raiha. This is the only file written in the
# nested form; every other file opens its module in the compact form
# (`module Raiha::TLS`), so a bare `TLS` or `QUIC` raises NameError instead
# of resolving to a neighbouring layer.
#
# Only `Raiha` is defined here. Defining the layer modules too would make
# `Raiha::QUIC` visible after `require "raiha/tls"`.
module Raiha
end
