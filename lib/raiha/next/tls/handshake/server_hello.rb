# frozen_string_literal: true

require_relative "../codec"
require_relative "../extension"
require_relative "message"

module Raiha::Next::TLS
  module Handshake
    # A ServerHello, or a HelloRetryRequest: RFC 9846 defines the latter as a
    # ServerHello whose random is a fixed value, not as a message type of its
    # own. The two differ only in which extensions they may carry, so parsing
    # picks the extension context from the random.
    class ServerHello < Data.define(
      :legacy_version, :random, :legacy_session_id_echo, :cipher_suite, :legacy_compression_method, :extensions
    )
      include Message
      include ExtensionLookup

      MSG_TYPE = 2

      HELLO_RETRY_REQUEST_RANDOM = ["CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"].pack("H*").freeze

      def self.parse_body(body, registry:)
        r = Codec::Reader.new(body)
        legacy_version = r.u16
        random = r.bytes(32)
        legacy_session_id_echo = r.opaque(1, max: 32)
        cipher_suite = r.u16
        legacy_compression_method = r.u8
        context = random == HELLO_RETRY_REQUEST_RANDOM ? :hello_retry_request : :server_hello #: Handshake::context
        extensions = Extension.read_list(r, context:, registry:, min: 6)
        r.finish!
        new(legacy_version:, random:, legacy_session_id_echo:, cipher_suite:, legacy_compression_method:, extensions:)
      end

      def msg_type = MSG_TYPE

      # The message type cannot tell the two apart, so a client must check
      # this on every ServerHello it receives.
      def hello_retry_request? = random == HELLO_RETRY_REQUEST_RANDOM

      def write_body(w)
        w.u16(legacy_version)
        w.bytes(random)
        w.vector(1, max: 32) { w.bytes(legacy_session_id_echo) }
        w.u16(cipher_suite)
        w.u8(legacy_compression_method)
        Extension.write_list(w, extensions, min: 6)
      end
    end
  end
end
