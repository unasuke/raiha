require "raiha/next/test_helper"
require "raiha/next/http3"

# The Capsules of RFC 9297 "The Capsule Protocol", their reading, and the
# Capsule-Protocol header field.
class RaihaNextHTTP3CapsuleTest < Minitest::Test
  HTTP3 = Raiha::Next::HTTP3
  Capsule = HTTP3::Capsule

  def read(*chunks, max_value: 100)
    reader = HTTP3::CapsuleReader.new(max_value:)
    [].tap { |all| chunks.each { |chunk| reader.feed(chunk.b) { all << _1 } } }
  end

  def test_encoding
    assert_equal "\x00\x05hello".b, Capsule.encode(Capsule.new(type: Capsule::DATAGRAM, value: "hello"))
    assert_equal "\x21\x00".b, Capsule.encode(Capsule.new(type: 0x21, value: ""))
    assert Ractor.shareable?(Capsule.new(type: 1, value: +"x"))
    assert_raises(ArgumentError) { Capsule.new(type: -1, value: "") }
  end

  def test_reading_however_the_bytes_are_cut
    bytes = Capsule.encode(Capsule.new(type: 0, value: "ping")) + Capsule.encode(Capsule.new(type: 0x1234, value: ""))
    expected = [Capsule.new(type: 0, value: "ping"), Capsule.new(type: 0x1234, value: "")]
    assert_equal expected, read(bytes)
    assert_equal expected, read(*bytes.chars)
  end

  # One too long to use is passed over without its bytes held.
  def test_a_capsule_too_long
    long = Capsule.encode(Capsule.new(type: 0, value: "x" * 101))
    assert_equal [Capsule.new(type: 1, value: "ok")], read(long, Capsule.encode(Capsule.new(type: 1, value: "ok")))
  end

  def test_mid_capsule
    reader = HTTP3::CapsuleReader.new(max_value: 100)
    refute reader.mid_capsule?
    reader.feed("\x00".b) { nil }
    assert reader.mid_capsule?
    reader.feed("\x01x".b) { nil }
    refute reader.mid_capsule?
  end

  # RFC 9297 "The Capsule-Protocol Header Field": an Item that is true,
  # once; and no content with it.
  def test_the_capsule_protocol_header_field
    assert HTTP3::Message.capsule_protocol?([["capsule-protocol", "?1"]])
    assert HTTP3::Message.capsule_protocol?([["capsule-protocol", "?1;foo=bar"]])
    refute HTTP3::Message.capsule_protocol?([["capsule-protocol", "?0"]])
    refute HTTP3::Message.capsule_protocol?([["capsule-protocol", "1"]])
    refute HTTP3::Message.capsule_protocol?([["capsule-protocol", "?1"], ["capsule-protocol", "?1"]])
    refute HTTP3::Message.capsule_protocol?([["capsule-protocol", "?1, ?1"]])
    refute HTTP3::Message.capsule_protocol?([])
    [[["content-length", "0"]], [["content-type", "text/plain"]]].each do |content|
      assert_raises(HTTP3::Message::Malformed) { HTTP3::Message.capsule_protocol?([["capsule-protocol", "?1"]] + content) }
    end
    assert_raises(HTTP3::Message::Malformed) { HTTP3::Message.capsule_protocol?([["capsule-protocol", "?1"]], status: 206) }
  end
end
