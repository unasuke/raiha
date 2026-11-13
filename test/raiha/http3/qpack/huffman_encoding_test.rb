require "test_helper"
require "raiha/http3/qpack"

# The Huffman code of RFC 7541 Appendix B, encoding side.
class RaihaNextQPACKHuffmanEncodingTest < Minitest::Test
  Huffman = Raiha::Next::HTTP3::QPACK::Huffman

  # RFC 7541 Appendix C.4 and C.6.
  EXAMPLES = {
    "www.example.com" => "f1e3c2e5f23a6ba0ab90f4ff",
    "no-cache" => "a8eb10649cbf",
    "custom-key" => "25a849e95ba97d7f",
    "custom-value" => "25a849e95bb8e8b4bf",
    "302" => "6402",
    "private" => "aec3771a4b",
    "Mon, 21 Oct 2013 20:13:21 GMT" => "d07abe941054d444a8200595040b8166e082a62d1bff",
    "https://www.example.com" => "9d29ad171863c78f0b97c8e9ae82ae43d3",
    "gzip" => "9bd9ab",
    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" =>
      "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"
  }.freeze

  def test_rfc7541_examples
    EXAMPLES.each do |plain, hex|
      assert_equal [hex].pack("H*"), Huffman.encode(plain.b), plain
      assert_equal hex.size / 2, Huffman.encoded_length(plain.b), plain
    end
  end

  def test_pads_with_the_most_significant_bits_of_eos
    assert_equal "\x07".b, Huffman.encode("0".b) # 00000 then 111
    assert_equal "".b, Huffman.encode("".b)
  end

  def test_encoded_length_matches_the_encoding
    random = Random.new(9204)
    strings = (0..255).map { |byte| byte.chr.b } + Array.new(200) { random.bytes(random.rand(0..64)) }
    strings.each do |string|
      assert_equal Huffman.encode(string).bytesize, Huffman.encoded_length(string), string.inspect
    end
  end

  # Every sequence of bits starts exactly one code: the lengths fill the
  # Kraft inequality to equality and no code is the prefix of another.
  def test_the_code_is_complete_and_prefix_free
    assert_equal 257, Huffman::CODES.size
    assert_equal 1 << 30, Huffman::CODES.sum { |_, length| 1 << (30 - length) }
    codes = Huffman::CODES.map { |code, length| code.to_s(2).rjust(length, "0") }.sort
    codes.each_cons(2) { |shorter, longer| refute longer.start_with?(shorter), "#{shorter} is a prefix of #{longer}" }
    assert_equal "1" * 30, codes.last # EOS
  end

  def test_tables_are_shareable
    assert Ractor.shareable?(Huffman::CODES)
    assert Ractor.shareable?(Huffman::BITS)
    assert Ractor.shareable?(Huffman::LENGTHS)
  end
end
