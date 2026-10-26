# frozen_string_literal: true

require_relative "namespace"

# HTTP/3. Does not know the TLS or QUIC layers.
module Raiha::Next::HTTP3
end

require_relative "http3/error_code"
require_relative "http3/varint"
require_relative "http3/frame"
