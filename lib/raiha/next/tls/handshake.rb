# frozen_string_literal: true

require_relative "codec"
require_relative "extension"
require_relative "handshake/message"
require_relative "handshake/client_hello"

module Raiha::Next::TLS
  # Handshake messages as values (RFC 9846 "Handshake Protocol"). Fields keep
  # the RFC's names, `legacy_` prefixes included, and enumerated values stay
  # Integers so unknown ones survive a round trip.
  module Handshake
    TYPES = {
      ClientHello::MSG_TYPE => ClientHello,
      # Only ever synthesized into the transcript after a HelloRetryRequest;
      # it never appears on the wire.
      254 => :message_hash
    }.freeze

    # Parses one handshake message, header included. Raises a
    # Codec::Malformed for anything that is not a well-formed message of a
    # known type; the state machine rejects unknown types before parsing.
    def self.parse(bytes, registry:)
      r = Codec::Reader.new(bytes)
      msg_type = r.u8
      body = r.opaque(3, max: 0xffffff)
      r.finish!
      parse_body(msg_type, body, registry:)
    end

    def self.parse_body(msg_type, body, registry:)
      case (klass = TYPES[msg_type])
      when nil, Symbol
        raise Codec::UnknownMessageType, "handshake message type #{msg_type} is not supported"
      else
        klass.parse_body(body, registry:)
      end
    end
  end
end
