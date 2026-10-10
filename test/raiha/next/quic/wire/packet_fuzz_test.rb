require "raiha/next/test_helper"
require "raiha/next/quic"
require "raiha/next/quic/test"

# A datagram from the network must never raise anything but Wire::Malformed
# while its coalesced packets are parsed, unmasked and opened, and a Retry's
# tag checked.
#
# Inputs are random byte strings, half of them after a long header's first
# byte and version 1, and the packets of RFC 9001 appendix A and a Version
# Negotiation packet, alone or coalesced, with one byte changed.
# RAIHA_FUZZ_ITERATIONS (default 10000) and RAIHA_FUZZ_SEED change the
# number of inputs and the seed.
class RaihaNextQUICWirePacketFuzzTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  Wire = QUIC::Wire
  V = QUIC::Test::Vectors

  ITERATIONS = Integer(ENV.fetch("RAIHA_FUZZ_ITERATIONS", "10000"))
  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "9001"))

  SAMPLES = [
    V::ClientInitial::PACKET, V::ServerInitial::PACKET, V::Retry::PACKET, V::ChaCha20ShortHeader::PACKET,
    V::ServerInitial::PACKET + V::ClientInitial::PACKET,
    Wire::VersionNegotiation.new(dcid: "d".b * 8, scid: "s".b * 8, versions: [1, 0x0a0a0a0a]).encode
  ].freeze

  INITIAL = QUIC::Crypto::Initial.derive(dcid: V::Keys::DCID, version: QUIC::Version::V1)
  SHORT = QUIC::Crypto::Keys.derive(suite: Raiha::Next::TLS::CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
    secret: V::ChaCha20ShortHeader::SECRET, version: QUIC::Version::V1)

  def random_input(rng)
    body = rng.bytes(rng.rand(0..1300))
    return body if rng.rand(2).zero?
    [0xc0 | rng.rand(0x40)].pack("C") + "\x00\x00\x00\x01".b + body
  end

  def mutated_input(rng)
    sample = SAMPLES.sample(random: rng).dup
    sample.setbyte(rng.rand(sample.bytesize), rng.rand(256))
    sample
  end

  # Goes through every packet in the datagram as the receiving end would,
  # and tells how many got as far as opening their payload.
  def receive(datagram, dcid_length)
    offset = 0
    opened = 0
    while offset < datagram.bytesize
      case packet = Wire::Packet.parse(datagram, offset:, dcid_length:)
      in Wire::Packet::Parsed
        keys = packet.header.is_a?(Wire::LongHeader) ? INITIAL.client : SHORT
        packet.unmask(keys.header_protection, largest: nil).open(keys.aead)
        opened += 1
        offset = packet.end_offset
      in Wire::Retry
        packet.authentic?(V::Keys::DCID)
        break
      in Wire::VersionNegotiation | Wire::UnsupportedVersion
        break
      end
    end
    opened
  end

  def test_receive_raises_only_malformed
    rng = Random.new(SEED)
    opened = 0
    ITERATIONS.times do |i|
      input = i.even? ? random_input(rng) : mutated_input(rng)
      dcid_length = [0, 8, rng.rand(0..20)].sample(random: rng)
      begin
        opened += receive(input, dcid_length)
      rescue Wire::Malformed
        nil
      rescue => e
        flunk "seed=#{SEED} iteration=#{i}: #{e.class}: #{e.message}\ninput=#{input.unpack1("H*")}\n#{e.backtrace.first(5).join("\n")}"
      end
    end
    # A run in which no packet gets past the header has stopped exercising
    # header protection and the AEAD.
    assert_operator opened, :>, 0
  end
end
