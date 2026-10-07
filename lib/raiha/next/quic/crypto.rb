# frozen_string_literal: true

require "openssl"

module Raiha::Next::QUIC
  # Everything in the QUIC layer that calls OpenSSL goes through here. Keys
  # are derived with the TLS layer's KeySchedule, so that both layers share
  # one HKDF-Expand-Label.
  module Crypto
  end
end

require_relative "crypto/aead"
require_relative "crypto/header_protection"
require_relative "crypto/keys"
require_relative "crypto/initial"
