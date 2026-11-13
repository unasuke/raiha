require "test_helper"
require "raiha/http3/qpack"

# RFC 9204 Appendix B, "Encoding and Decoding Examples", from the
# decoder's side: the encoder's instructions and sections in, the fields
# and the decoder's instructions out, with a table of 220 octets.
class RaihaNextQPACKRFC9204ExamplesTest < Minitest::Test
  QPACK = Raiha::HTTP3::QPACK

  def setup
    @decoder = QPACK::Decoder.new(max_table_capacity: 220, max_blocked_streams: 1)
  end

  # Appendix B.1.
  def test_literal_field_line_with_name_reference
    assert_equal [field(":path", "/index.html")], @decoder.decode(0, hex("0000 510b 2f69 6e64 6578 2e68 746d 6c")).fields
    assert_equal "".b, @decoder.take_instructions
  end

  # Appendix B.2 to B.5, in order.
  def test_the_exchange
    # B.2: a capacity, two insertions, and a section after the Base.
    assert_equal [], @decoder.receive_encoder_stream(hex(<<~HEX))
      3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468
    HEX
    decoded = @decoder.decode(4, hex("0381 10 11"))
    assert_equal [field(":authority", "www.example.com"), field(":path", "/sample/path")], decoded.fields
    assert_equal hex("84"), @decoder.take_instructions

    # B.3: an insertion no section refers to.
    assert_equal [], @decoder.receive_encoder_stream(hex("4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565"))
    assert_equal hex("01"), @decoder.take_instructions

    # B.4: a section that comes before the Duplicate it refers to, and is
    # cancelled.
    assert_equal QPACK::Blocked.new(stream_id: 8), @decoder.decode(8, hex("0500 80 c1 81"))
    @decoder.cancel(8)
    assert_equal hex("48"), @decoder.take_instructions
    assert_equal [], @decoder.receive_encoder_stream(hex("02"))
    assert_equal [field(":authority", "www.example.com"), field(":path", "/"), field("custom-key", "custom-value")],
      @decoder.decode(12, hex("0500 80 c1 81")).fields

    # B.5: an insertion that evicts the oldest entry, :authority.
    assert_equal [], @decoder.receive_encoder_stream(hex("810d 6375 7374 6f6d 2d76 616c 7565 32"))
    assert_equal [field("custom-key", "custom-value2")], @decoder.decode(16, hex("0600 80")).fields
    failure = @decoder.decode(20, hex("0600 84"))
    assert_equal QPACK::ErrorCode::DECOMPRESSION_FAILED, failure.code
    assert_match(/evicted/, failure.reason)
  end

  private def field(name, value) = QPACK::Field.new(name: name.b, value: value.b)

  private def hex(text) = [text.delete(" \n")].pack("H*")
end
