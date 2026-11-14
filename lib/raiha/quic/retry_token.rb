# frozen_string_literal: true

module Raiha::QUIC
  # The token of a Retry packet (RFC 9000 "Address Validation Using Retry
  # Packets"). It comes back on the client's next Initial and shows the
  # server, which keeps nothing in between, that the client receives at the
  # address it sends from, and what the client's first Destination
  # Connection ID was:
  #
  #   kind (0, a Retry token) || expiry (8 bytes, seconds since the epoch)
  #   || ODCID length (1) || ODCID || MAC (32)
  #
  # The MAC is HMAC-SHA256 under the Endpoint's retry_token_key over all
  # before it and the client's address, which the token does not carry. The
  # kind tells it from the tokens of NEW_TOKEN frames, which the server must
  # be able to (RFC 9000 "Address Validation for Future Connections"); it
  # lives `LIFETIME` seconds of the wall clock, which every worker shares.
  module RetryToken
    KIND = 0
    LIFETIME = 10
    EXPIRY_LENGTH = 8
    # kind, expiry, the ODCID's length and the MAC.
    OVERHEAD = 1 + EXPIRY_LENGTH + 1 + Crypto::Mac::LENGTH

    def self.mint(key:, original_destination_connection_id:, address:, time:)
      odcid = original_destination_connection_id
      body = [KIND, time.to_i + LIFETIME, odcid.bytesize].pack("CQ>C") + odcid
      body + Crypto::Mac.digest(key, body + bound(address))
    end

    # The ODCID of a token made for `address` that has not expired, nil for
    # any other.
    def self.verify(token, key:, address:, time:)
      return nil if token.bytesize < OVERHEAD || token.getbyte(0) != KIND
      body = token.byteslice(0, token.bytesize - Crypto::Mac::LENGTH) #: String
      mac = token.byteslice(body.bytesize, Crypto::Mac::LENGTH) #: String
      return nil unless Crypto::Mac.same?(mac, Crypto::Mac.digest(key, body + bound(address)))
      expiry = body.unpack1("Q>", offset: 1)
      odcid_length = body.unpack1("C", offset: 1 + EXPIRY_LENGTH)
      return nil if time.to_i > expiry || body.bytesize != OVERHEAD - Crypto::Mac::LENGTH + odcid_length
      body.byteslice(OVERHEAD - Crypto::Mac::LENGTH, odcid_length)
    end

    private_class_method def self.bound(address) = "#{address.fetch(0)}\0".b + [address.fetch(1)].pack("n")
  end
end
