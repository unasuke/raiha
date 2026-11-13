# frozen_string_literal: true

module Raiha::TLS
  # The TLS record layer, used over TCP only (Profile::TCP). QUIC carries
  # handshake messages in CRYPTO frames and protects packets itself.
  module Record
  end
end

require_relative "record/protection"
require_relative "record/layer"
