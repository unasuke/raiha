# frozen_string_literal: true

module Raiha::Next::TLS
  # Extension values. Each class keeps the RFC's field names and follows the
  # contract an `Extension::Registry` relies on: `.parse(String)`,
  # `#extension_type` and `#encode`, where the String is the extension_data.
  #
  # An extension whose structure depends on the message it rides in has one
  # class per message (`KeyShare::CH`, `KeyShare::SH`, ...), so the type says
  # which combination is valid.
  module Extension
  end
end

require_relative "extension/opaque"
require_relative "extension/server_name"
require_relative "extension/supported_groups"
require_relative "extension/signature_algorithms"
require_relative "extension/signature_algorithms_cert"
require_relative "extension/alpn"
require_relative "extension/psk_key_exchange_modes"
require_relative "extension/cookie"
require_relative "extension/record_size_limit"
require_relative "extension/certificate_authorities"
require_relative "extension/post_handshake_auth"
require_relative "extension/compress_certificate"
