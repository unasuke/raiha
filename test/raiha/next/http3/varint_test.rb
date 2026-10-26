require "raiha/next/test_helper"
require "raiha/next/http3"

class RaihaNextHTTP3VarintTest < Minitest::Test
  Varint = Raiha::Next::HTTP3::Varint

  # The examples of RFC 9000 "Sample Variable-Length Integer Decoding".
  EXAMPLES = {
    ["c2197c5eff14e88c"].pack("H*") => 151_288_809_941_952_652,
    ["9d7f3e7d"].pack("H*") => 494_878_333,
    ["7bbd"].pack("H*") => 15_293,
    ["25"].pack("H*") => 37
  }.freeze

  def test_the_examples_of_rfc_9000
    EXAMPLES.each do |bytes, value|
      assert_equal [value, bytes.bytesize], Varint.decode(bytes)
      assert_equal bytes, Varint.encode(value)
    end
    assert_equal [37, 2], Varint.decode(["4025"].pack("H*"))
  end

  def test_sizes
    assert_equal [1, 2, 2, 4, 4, 8, 8], [63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, Varint::MAX].map { Varint.size(_1) }
    [-1, Varint::MAX + 1, 1.0].each { |value| assert_raises(ArgumentError) { Varint.encode(value) } }
  end

  def test_decoding_from_an_offset
    bytes = "\xff\x40\x25\x07".b
    assert_equal [37, 3], Varint.decode(bytes, 1)
    assert_equal [7, 4], Varint.decode(bytes, 3)
  end

  def test_nil_when_the_bytes_end_first
    assert_nil Varint.decode("".b)
    assert_nil Varint.decode("\x9d\x7f\x3e".b)
    assert_nil Varint.decode("\x25".b, 1)
  end
end
