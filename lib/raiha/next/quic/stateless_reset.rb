# frozen_string_literal: true

module Raiha::Next::QUIC
  # RFC 9000 "Stateless Reset": what an endpoint that has lost a
  # connection sends to end it, which looks like a short header packet but
  # ends in the token the endpoint gave out with the connection ID.
  module StatelessReset
    TOKEN_LENGTH = 16
    # The shortest a reset is: a short header packet with a 1-byte packet
    # number and an AEAD tag, which RFC 9000 asks a reset to be as long as.
    MIN_LENGTH = 21

    # The token of `connection_id`, which only the holder of `key` can make
    # and which no state is kept for (RFC 9000 "Calculating a Stateless Reset
    # Token"): HMAC-SHA256 of the connection ID, cut to 16 bytes.
    def self.token(key:, connection_id:)
      Crypto::Mac.digest(key, connection_id).byteslice(0, TOKEN_LENGTH) #: String
    end

    # A reset of `length` bytes ending in `token`: random bytes from `random`
    # under a first byte with the form bit clear and the fixed bit set.
    def self.packet(token:, length:, random:)
      raise ArgumentError, "a stateless reset is #{MIN_LENGTH} bytes at least, not #{length}" if length < MIN_LENGTH
      unpredictable = random.bytes(length - TOKEN_LENGTH).b
      first = unpredictable.getbyte(0) #: Integer
      unpredictable.setbyte(0, (first & 0x3f) | 0x40)
      unpredictable + token
    end

    # Whether `datagram` ends in one of `tokens`, each compared in constant
    # time.
    def self.match?(datagram, tokens)
      return false if datagram.bytesize < MIN_LENGTH
      tail = datagram.byteslice(-TOKEN_LENGTH, TOKEN_LENGTH) #: String
      tokens.any? { |token| Crypto::Mac.same?(tail, token) }
    end
  end
end
