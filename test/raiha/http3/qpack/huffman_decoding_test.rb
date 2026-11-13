require "test_helper"
require "raiha/http3/qpack"

# The Huffman code of RFC 7541 Appendix B, decoding side: a byte at a time
# through the transitions of a DFA.
class RaihaNextQPACKHuffmanDecodingTest < Minitest::Test
  QPACK = Raiha::Next::HTTP3::QPACK
  Huffman = QPACK::Huffman

  # RFC 7541 Appendix C.4 and C.6.
  def test_rfc7541_examples
    {
      "f1e3c2e5f23a6ba0ab90f4ff" => "www.example.com",
      "a8eb10649cbf" => "no-cache",
      "25a849e95bb8e8b4bf" => "custom-value",
      "6402" => "302",
      "d07abe941054d444a8200595040b8166e082a62d1bff" => "Mon, 21 Oct 2013 20:13:21 GMT",
      "9d29ad171863c78f0b97c8e9ae82ae43d3" => "https://www.example.com"
    }.each do |hex, plain|
      assert_equal plain.b, Huffman.decode([hex].pack("H*"))
    end
  end

  def test_round_trip
    random = Random.new(7541)
    strings = (0..255).map { |byte| byte.chr.b } + Array.new(300) { random.bytes(random.rand(0..100)) }
    strings.each do |string|
      decoded = Huffman.decode(Huffman.encode(string))
      assert_equal string, decoded
      assert_equal Encoding::BINARY, decoded.encoding
    end
  end

  # RFC 7541 "String Literal Representation": padding is the most
  # significant bits of EOS, at most seven of them.
  def test_padding
    assert_equal "0".b, Huffman.decode("\x07".b)
    assert_equal "".b, Huffman.decode("".b)
    assert_raises(QPACK::Malformed) { Huffman.decode("\x07\xff".b) }  # eight bits of padding
    assert_raises(QPACK::Malformed) { Huffman.decode("\x06".b) }      # padding of other than ones
    assert_raises(QPACK::Malformed) { Huffman.decode("\xfe".b) }      # a code cut short, not padding
  end

  def test_eos_is_an_error
    assert_raises(QPACK::Malformed) { Huffman.decode("\xff\xff\xff\xff".b) }
    assert_raises(QPACK::Malformed) { Huffman.decode("\xff\xff\xff\xfc\x07".b) } # EOS, then "0"
  end

  # The transitions agree with walking the tree a bit at a time on any
  # bytes, valid or not.
  def test_agrees_with_walking_the_tree
    tree = Huffman.tree_of(Huffman::CODES)
    random = Random.new(9204)
    inputs = Array.new(2_000) { random.bytes(random.rand(0..12)) } +
      Array.new(500) { Huffman.encode(random.bytes(random.rand(0..20))) }
    inputs.each do |bytes|
      expected = walk(tree, bytes)
      if expected
        assert_equal expected, Huffman.decode(bytes), bytes.unpack1("H*")
      else
        assert_raises(QPACK::Malformed, bytes.unpack1("H*")) { Huffman.decode(bytes) }
      end
    end
  end

  def test_tables_are_shareable
    assert Ractor.shareable?(Huffman::NEXT_STATES)
    assert Ractor.shareable?(Huffman::EMITS)
    assert Ractor.shareable?(Huffman::ACCEPTING)
  end

  # The octets `bytes` decode to, or nil where they do not.
  private def walk(tree, bytes)
    decoded = "".b
    node = 0
    bits = 0
    bytes.unpack1("B*").each_char do |bit|
      child = tree[node][bit.to_i]
      if child.negative?
        return nil if ~child == Huffman::EOS
        decoded << ~child
        node = 0
        bits = 0
      else
        node = child
        bits += 1
      end
    end
    return decoded if node.zero?
    padding = bytes.unpack1("B*")[-bits..]
    bits <= 7 && padding == "1" * bits ? decoded : nil
  end
end
