require "test_helper"
require "raiha/http3/qpack/huffman"

class RaihaHTTP3QPACKHuffmanTest < Minitest::Test
  # RFC 7541 Appendix C.4.1 test vector:
  # "www.example.com" encodes to Huffman bytes f1e3c2e5f23a6ba0ab90f4ff
  def test_decode_www_example_com_from_rfc7541
    encoded = ["f1e3c2e5f23a6ba0ab90f4ff"].pack("H*")
    assert_equal "www.example.com", Raiha::HTTP3::QPACK::Huffman.decode(encoded)
  end

  # RFC 7541 Appendix C.4.2: "no-cache" → a8eb10649cbf
  def test_decode_no_cache_from_rfc7541
    encoded = ["a8eb10649cbf"].pack("H*")
    assert_equal "no-cache", Raiha::HTTP3::QPACK::Huffman.decode(encoded)
  end

  # RFC 7541 Appendix C.4.3: "custom-key" → 25a849e95ba97d7f
  # and "custom-value" → 25a849e95bb8e8b4bf
  def test_decode_custom_key
    encoded = ["25a849e95ba97d7f"].pack("H*")
    assert_equal "custom-key", Raiha::HTTP3::QPACK::Huffman.decode(encoded)
  end

  def test_decode_custom_value
    encoded = ["25a849e95bb8e8b4bf"].pack("H*")
    assert_equal "custom-value", Raiha::HTTP3::QPACK::Huffman.decode(encoded)
  end

  def test_decode_empty
    assert_equal "", Raiha::HTTP3::QPACK::Huffman.decode("")
  end

  def test_decode_rejects_eos_in_payload
    # The EOS code is 0x3fffffff (30 bits). A full 30-bit EOS followed by padding
    # would be at least 4 bytes. Construct 4 bytes of all-1s which includes an EOS.
    encoded = "\xff\xff\xff\xff".b
    assert_raises(Raiha::HTTP3::QPACK::Huffman::DecodingError) do
      Raiha::HTTP3::QPACK::Huffman.decode(encoded)
    end
  end

  def test_decode_rejects_padding_longer_than_7_bits
    # "0" (symbol 48 = 0x00, 5 bits) + 11 bits of "1" padding should be rejected.
    # Encoded: 00000 11111111111 → 0000 0111 1111 1111 = 0x07FF (2 bytes, 16 bits)
    # That's 5+11=16 bits total, 11 > 7 padding bits after symbol.
    encoded = "\x07\xff".b
    assert_raises(Raiha::HTTP3::QPACK::Huffman::DecodingError) do
      Raiha::HTTP3::QPACK::Huffman.decode(encoded)
    end
  end

  def test_decode_rejects_invalid_padding_bits
    # "0" (5 bits "00000") followed by 3 bits of "000" padding.
    # Encoded byte: 0000 0000 = 0x00. Padding must be all 1s.
    encoded = "\x00".b
    assert_raises(Raiha::HTTP3::QPACK::Huffman::DecodingError) do
      Raiha::HTTP3::QPACK::Huffman.decode(encoded)
    end
  end
end
