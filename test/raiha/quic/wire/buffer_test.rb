require "test_helper"
require "raiha/quic/wire/buffer"

class RaihaQuicWireBufferTest < Minitest::Test
  def test_read_write_uint8
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_uint8(0xff)
    buf.seek(0)
    assert_equal 0xff, buf.read_uint8
  end

  def test_read_write_uint16
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_uint16(0xabcd)
    buf.seek(0)
    assert_equal 0xabcd, buf.read_uint16
  end

  def test_read_write_uint32
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_uint32(0xdeadbeef)
    buf.seek(0)
    assert_equal 0xdeadbeef, buf.read_uint32
  end

  def test_read_write_varint
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_varint(494878333)
    buf.seek(0)
    assert_equal 494878333, buf.read_varint
  end

  def test_parse_from_data
    data = "\x03\x00\x10hello".b
    buf = Raiha::Quic::Wire::Buffer.new(data)
    assert_equal 3, buf.read_uint8
    assert_equal 16, buf.read_uint16
    assert_equal "hello", buf.read(5)
  end

  def test_remaining
    buf = Raiha::Quic::Wire::Buffer.new("\x01\x02\x03".b)
    assert_equal 3, buf.remaining
    buf.read(1)
    assert_equal 2, buf.remaining
  end

  def test_eof
    buf = Raiha::Quic::Wire::Buffer.new("\x01".b)
    refute buf.eof?
    buf.read(1)
    assert buf.eof?
  end

  def test_to_s
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_uint8(0x42)
    buf.write_uint8(0x43)
    assert_equal "\x42\x43".b, buf.to_s
  end
end
