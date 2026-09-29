# frozen_string_literal: true

require_relative "namespace"

# TLS 1.3. Depends on nothing but openssl.
module Raiha::Next::TLS
end

require_relative "tls/codec"
require_relative "tls/iana"
require_relative "tls/extension"
require_relative "tls/handshake"
