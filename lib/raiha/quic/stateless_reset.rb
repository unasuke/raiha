# frozen_string_literal: true

require "openssl"
require "securerandom"

require_relative "error"
require_relative "protocol/connection_id"

module Raiha::Quic
  # RFC 9000 §10.3 Stateless Reset.
  #
  # A stateless reset is the last-resort signal an endpoint sends when it has
  # lost connection state and receives a packet it cannot match to a
  # connection. The packet is indistinguishable on the wire from a short
  # header packet, except the last 16 bytes are a token that the peer issued
  # during the handshake (via a NEW_CONNECTION_ID frame or the
  # stateless_reset_token transport parameter). The receiver that owns that
  # token can detect the reset by comparing the trailing 16 bytes against
  # tokens it remembers for the connection.
  module StatelessReset
    TOKEN_LENGTH = 16

    # RFC §10.3: a stateless reset datagram MUST be at least 21 bytes so it
    # cannot be mistaken for a header-only short packet.
    MIN_PACKET_LENGTH = 21

    # Build a stateless reset packet. `token` is the 16-byte stateless
    # reset token the endpoint advertised for the connection ID whose
    # packet triggered the reset. `min_size` controls the total length of
    # the emitted packet (always at least MIN_PACKET_LENGTH).
    def self.build(token, min_size: MIN_PACKET_LENGTH)
      raise ArgumentError, "stateless reset token must be #{TOKEN_LENGTH} bytes" unless token.bytesize == TOKEN_LENGTH

      effective_size = [min_size, MIN_PACKET_LENGTH].max
      unpredictable_length = effective_size - TOKEN_LENGTH
      unpredictable = SecureRandom.random_bytes(unpredictable_length)

      # RFC §17.2/§17.3: bit 7 of the first byte is the header form (0 for
      # short headers) and bit 6 is the fixed bit (always 1). The remaining
      # six bits are unpredictable and indistinguishable from a genuine
      # short header packet.
      first_byte = (unpredictable.getbyte(0) & 0x3f) | 0x40 #: Integer
      unpredictable.setbyte(0, first_byte)

      unpredictable + token
    end

    # RFC 9000 §10.3.1: derive a stateless reset token deterministically
    # from a static, server-wide reset key and the connection ID that
    # the server picked when issuing it. HMAC-SHA256 truncated to 16
    # bytes gives the required pseudo-randomness without keeping any
    # per-CID state.
    def self.derive_token(reset_key, connection_id)
      raise ArgumentError, "reset_key must not be empty" if reset_key.nil? || reset_key.empty?

      cid_bytes = connection_id.is_a?(Protocol::ConnectionID) ? connection_id.serialize : connection_id
      OpenSSL::HMAC.digest("SHA256", reset_key, cid_bytes).byteslice(0, TOKEN_LENGTH) or
        raise Raiha::Quic::Error, "TODO: HMAC byteslice failed in derive_token"
    end

    # Return true when the datagram's trailing 16 bytes match any of the
    # supplied known tokens. Callers typically pass the set of tokens the
    # peer advertised for active connection IDs plus the peer's
    # stateless_reset_token transport parameter.
    def self.match_token?(datagram, tokens)
      return false if datagram.bytesize < MIN_PACKET_LENGTH
      return false if tokens.empty?

      trailing = datagram.byteslice(-TOKEN_LENGTH, TOKEN_LENGTH)
      tokens.include?(trailing)
    end
  end
end
