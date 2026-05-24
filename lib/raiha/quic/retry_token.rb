# frozen_string_literal: true

require "openssl"

module Raiha::Quic
  # Stateless cookie carried in a Retry packet to prove that the
  # repeated Initial came from the same address that the server saw
  # the first time around (RFC 9000 §8.1.2). The token is opaque to
  # clients; only the issuing server validates it.
  #
  # Format: payload = expiry(8) || odcid_length(1) || odcid(0..20) ||
  #                   client_address (whatever bytes the caller binds
  #                                    the token to)
  #         token   = payload || HMAC-SHA256(retry_key, payload)
  #
  # Verification re-derives the HMAC and refuses tokens whose
  # expiry has passed. The client_address bytes are reconstructed by
  # the caller from the network metadata of the second Initial, so
  # spoofing requires forging both the IP / port (already covered by
  # network-level validation) and the HMAC.
  module RetryToken
    HMAC_LENGTH = 32
    EXPIRY_BYTES = 8

    DEFAULT_LIFETIME = 30 # seconds

    # Issue a token. `peer_address_bytes` is any opaque byte string
    # that uniquely identifies the address the server saw the first
    # Initial from (e.g. packed IP + port). `original_destination_connection_id`
    # must be the DCID the client actually sent — not the new one the
    # server is about to advertise via the Retry SCID.
    def self.mint(retry_key:, peer_address_bytes:, original_destination_connection_id:, lifetime: DEFAULT_LIFETIME, now: Time.now)
      raise ArgumentError, "retry_key must not be empty" if retry_key.nil? || retry_key.empty?

      odcid_bytes = original_destination_connection_id.is_a?(Protocol::ConnectionID) ?
                      original_destination_connection_id.serialize :
                      original_destination_connection_id

      expiry = now.to_i + lifetime
      payload = String.new(encoding: "BINARY")
      payload << [expiry].pack("Q>")
      payload << [odcid_bytes.bytesize].pack("C")
      payload << odcid_bytes
      payload << peer_address_bytes

      payload + OpenSSL::HMAC.digest("SHA256", retry_key, payload)
    end

    # Verify `token`, returning the original DCID bytes when it is
    # valid (HMAC matches, not expired, peer address matches what
    # was bound at mint time). Returns nil otherwise.
    def self.verify(retry_key:, token:, peer_address_bytes:, now: Time.now)
      return nil if retry_key.nil? || retry_key.empty?
      return nil if token.bytesize < EXPIRY_BYTES + 1 + HMAC_LENGTH

      payload = token.byteslice(0, token.bytesize - HMAC_LENGTH) #: String
      received_hmac = token.byteslice(-HMAC_LENGTH, HMAC_LENGTH) #: String

      expected_hmac = OpenSSL::HMAC.digest("SHA256", retry_key, payload)
      return nil unless OpenSSL.fixed_length_secure_compare(expected_hmac, received_hmac)

      expiry = payload.byteslice(0, EXPIRY_BYTES).unpack1("Q>")
      return nil if now.to_i > expiry

      odcid_length = payload.getbyte(EXPIRY_BYTES)
      return nil unless odcid_length
      odcid_offset = EXPIRY_BYTES + 1
      return nil if payload.bytesize < odcid_offset + odcid_length

      odcid = payload.byteslice(odcid_offset, odcid_length) #: String
      bound_address = payload.byteslice(odcid_offset + odcid_length, payload.bytesize) #: String
      return nil unless bound_address == peer_address_bytes

      odcid
    end
  end
end
