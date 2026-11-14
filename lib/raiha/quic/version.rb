# frozen_string_literal: true

module Raiha::QUIC
  # What changes between QUIC versions, in one value, so that no other code
  # writes a version's literals: the version number, the salt of the Initial
  # secrets, the prefix of the key derivation labels, the long header packet
  # types, and the key and nonce of the Retry integrity tag. RFC 9369 (QUIC
  # version 2) changes every one of them, the packet type bits included.
  class Version < Data.define(:number, :initial_salt, :label_prefix, :packet_types, :retry_key, :retry_nonce)
    LONG_PACKET_TYPES = %i[initial zero_rtt handshake retry].freeze

    # The packet protection label `name` ("key", "iv", "hp", "ku").
    def label(name) = "#{label_prefix} #{name}"

    # The two type bits of a long header packet of `type`.
    def type_bits(type) = packet_types.fetch(type) { raise ArgumentError, "no long header packet type #{type.inspect}" }

    # The packet type the two `bits` stand for.
    def packet_type(bits) = packet_types.key(bits) || raise(ArgumentError, "type bits are 0..3, not #{bits.inspect}")

    # RFC 9000 and RFC 9001 ("Initial Secrets", "Retry Packet Integrity").
    V1 = Ractor.make_shareable(new(
      number: 0x0000_0001,
      initial_salt: ["38762cf7f55934b34d179ae6a4c80cadccbb7f0a"].pack("H*"),
      label_prefix: "quic",
      packet_types: { initial: 0b00, zero_rtt: 0b01, handshake: 0b10, retry: 0b11 },
      retry_key: ["be0c690b9f66575a1d766b54e368c84e"].pack("H*"),
      retry_nonce: ["461599d35d632bf2239825bb"].pack("H*")
    ))

    SUPPORTED = [V1].freeze

    # The supported Version numbered `number`, or nil.
    def self.find(number) = SUPPORTED.find { |version| version.number == number }
  end
end
