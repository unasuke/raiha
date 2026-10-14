require "raiha/next/test_helper"
require "raiha/next/quic"
require "raiha/next/quic/test"

# RFC 9001 "Packet Protection": the keys of each encryption level.
class RaihaNextQUICPacketProtectionTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  V = QUIC::Test::Vectors
  SUITE = Raiha::Next::TLS::CipherSuite::TLS_AES_128_GCM_SHA256

  def protection(role) = QUIC::PacketProtection.new(role:, version: QUIC::Version::V1)

  def seal(keys) = keys.aead.seal(packet_number: 0, header: "h".b, plaintext: "p".b)

  # Each end writes with its own Initial keys and reads with the other's
  # (RFC 9001 appendix A.1).
  def test_initial
    client = protection(:client)
    server = protection(:server)
    refute client.can_write?(:initial)
    client.install_initial(V::Keys::DCID)
    server.install_initial(V::Keys::DCID)
    c = V::ClientInitial
    plaintext = c::FRAMES.ljust(c::PAYLOAD_LENGTH, "\0".b)
    assert_equal_bin c::PACKET.byteslice(c::HEADER.bytesize..),
      client.write_keys(:initial).aead.seal(packet_number: c::PACKET_NUMBER, header: c::HEADER, plaintext:)
    assert_equal seal(client.write_keys(:initial)), seal(server.read_keys(:initial))
    assert_equal seal(server.write_keys(:initial)), seal(client.read_keys(:initial))
  end

  def test_secrets_from_tls
    protection = protection(:client)
    secret = "s".b * 32
    protection.install(:handshake, :write, secret:, suite: SUITE)
    assert protection.can_write?(:handshake)
    refute protection.can_read?(:handshake)
    assert_equal seal(QUIC::Crypto::Keys.derive(suite: SUITE, secret:, version: QUIC::Version::V1)), seal(protection.write_keys(:handshake))
    assert_raises(ArgumentError) { protection.install(:initial, :read, secret:, suite: SUITE) }
  end

  # A level discarded stays so.
  def test_discard
    protection = protection(:client)
    protection.install_initial(V::Keys::DCID)
    protection.discard(:initial)
    refute protection.can_read?(:initial)
    refute protection.can_write?(:initial)
    assert protection.discarded?(:initial)
    protection.install(:handshake, :read, secret: "s".b * 32, suite: SUITE)
    protection.discard(:handshake)
    assert_raises(ArgumentError) { protection.install(:handshake, :read, secret: "s".b * 32, suite: SUITE) }
  end
end
