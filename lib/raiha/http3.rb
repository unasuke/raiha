# frozen_string_literal: true

require_relative "namespace"

# HTTP/3. Does not know the TLS or QUIC layers.
module Raiha::Next::HTTP3
end

require_relative "http3/error_code"
require_relative "http3/error"
require_relative "http3/varint"
require_relative "http3/frame"
require_relative "http3/frame_reader"
require_relative "http3/settings"
require_relative "http3/priority"
require_relative "http3/action"
require_relative "http3/output"
require_relative "http3/connection"
require_relative "http3/qlog"
