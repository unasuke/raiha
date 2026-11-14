require "test_helper"
require "raiha/quic"

class RaihaQUICVersionTest < Minitest::Test
  Version = Raiha::QUIC::Version

  def hex(s) = [s].pack("H*")

  # RFC 9001 "Initial Secrets" and "Retry Packet Integrity"; RFC 9000
  # "Long Header Packets".
  def test_v1
    v1 = Version::V1
    assert_equal 1, v1.number
    assert_equal_bin hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), v1.initial_salt
    assert_equal_bin hex("be0c690b9f66575a1d766b54e368c84e"), v1.retry_key
    assert_equal_bin hex("461599d35d632bf2239825bb"), v1.retry_nonce
    assert_equal %w[quic\ key quic\ iv quic\ hp quic\ ku], %w[key iv hp ku].map { |name| v1.label(name) }
    assert_equal [0, 1, 2, 3], Version::LONG_PACKET_TYPES.map { |type| v1.type_bits(type) }
    assert_equal Version::LONG_PACKET_TYPES, (0..3).map { |bits| v1.packet_type(bits) }
    assert Ractor.shareable?(v1)
  end

  def test_find
    assert_same Version::V1, Version.find(1)
    assert_nil Version.find(0x6b3343cf)
    assert_nil Version.find(0)
  end

  def test_misuse
    assert_raises(ArgumentError) { Version::V1.type_bits(:one_rtt) }
    assert_raises(ArgumentError) { Version::V1.packet_type(4) }
  end
end
