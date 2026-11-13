# frozen_string_literal: true

require_relative "codec"
require_relative "extension"
require_relative "handshake/message"
require_relative "handshake/violation"
require_relative "handshake/client_hello"
require_relative "handshake/server_hello"
require_relative "handshake/encrypted_extensions"
require_relative "handshake/certificate_request"
require_relative "handshake/certificate"
require_relative "handshake/certificate_verify"
require_relative "handshake/finished"
require_relative "handshake/new_session_ticket"
require_relative "handshake/end_of_early_data"
require_relative "handshake/key_update"
require_relative "handshake/reassembler"
require_relative "handshake/client_hello_builder"
require_relative "handshake/machine"

module Raiha::TLS
  # Handshake messages as values (RFC 9846 "Handshake Protocol"). Fields keep
  # the RFC's names, `legacy_` prefixes included, and enumerated values stay
  # Integers so unknown ones survive a round trip.
  module Handshake
    TYPES = {
      ClientHello::MSG_TYPE => ClientHello,
      ServerHello::MSG_TYPE => ServerHello,
      NewSessionTicket::MSG_TYPE => NewSessionTicket,
      EndOfEarlyData::MSG_TYPE => EndOfEarlyData,
      EncryptedExtensions::MSG_TYPE => EncryptedExtensions,
      Certificate::MSG_TYPE => Certificate,
      CertificateRequest::MSG_TYPE => CertificateRequest,
      CertificateVerify::MSG_TYPE => CertificateVerify,
      Finished::MSG_TYPE => Finished,
      KeyUpdate::MSG_TYPE => KeyUpdate,
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
