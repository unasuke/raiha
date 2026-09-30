# frozen_string_literal: true

require "openssl"

module Raiha::Next::TLS
  # Everything in the TLS layer that calls OpenSSL goes through here (or
  # Verifier). Keeping the calls in one place keeps OpenSSL's API quirks and
  # version checks out of the protocol code.
  module Crypto
  end
end

require_relative "crypto/hash"
require_relative "crypto/digest"
require_relative "crypto/hkdf"
require_relative "crypto/ecdh"
