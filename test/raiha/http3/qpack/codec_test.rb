require "test_helper"
require "raiha/http3/qpack/encoder"
require "raiha/http3/qpack/decoder"

class RaihaHTTP3QPACKCodecTest < Minitest::Test
  def setup
    @encoder = Raiha::HTTP3::QPACK::Encoder.new
    @decoder = Raiha::HTTP3::QPACK::Decoder.new
  end

  def test_roundtrip_indexed_field_line
    headers = [[":method", "GET"], [":scheme", "https"], [":status", "200"]]
    encoded = @encoder.encode(headers)
    decoded = @decoder.decode(encoded)

    assert_equal headers, decoded
  end

  def test_roundtrip_literal_with_name_reference
    headers = [[":path", "/api/v1/users"], [":authority", "example.com"]]
    encoded = @encoder.encode(headers)
    decoded = @decoder.decode(encoded)

    assert_equal headers, decoded
  end

  def test_roundtrip_literal_with_literal_name
    headers = [["x-custom-header", "custom-value"]]
    encoded = @encoder.encode(headers)
    decoded = @decoder.decode(encoded)

    assert_equal headers, decoded
  end

  def test_roundtrip_mixed_headers
    headers = [
      [":method", "POST"],
      [":scheme", "https"],
      [":path", "/submit"],
      [":authority", "api.example.com"],
      ["content-type", "application/json"],
      ["content-length", "42"],
      ["x-request-id", "abc-123-def"],
    ]
    encoded = @encoder.encode(headers)
    decoded = @decoder.decode(encoded)

    assert_equal headers, decoded
  end

  def test_encoded_starts_with_zero_prefix
    # Static-only encoding: Required Insert Count = 0, Delta Base = 0
    headers = [[":method", "GET"]]
    encoded = @encoder.encode(headers)
    assert_equal "\x00\x00\xd1".b, encoded
  end

  def test_indexed_field_line_encoding
    # :method GET is index 17 in static table
    # Pattern: 1 T xxxxxx → 0xc0 | 17 = 0xd1
    encoded = @encoder.encode([[":method", "GET"]])
    assert_equal 3, encoded.bytesize # 2 prefix + 1 field line
    assert_equal 0xd1, encoded.getbyte(2)
  end

  def test_header_name_lowercased
    # HTTP/2 and HTTP/3 require lowercase header names
    encoded = @encoder.encode([["Content-Type", "text/plain"]])
    decoded = @decoder.decode(encoded)
    assert_equal [["content-type", "text/plain"]], decoded
  end

  def test_decode_empty_headers
    encoded = @encoder.encode([])
    assert_equal [], @decoder.decode(encoded)
  end

  def test_empty_value_roundtrip
    headers = [["user-agent", ""]]
    encoded = @encoder.encode(headers)
    assert_equal headers, @decoder.decode(encoded)
  end

  def test_long_value_roundtrip
    long_value = "x" * 300
    headers = [["x-long", long_value]]
    encoded = @encoder.encode(headers)
    assert_equal headers, @decoder.decode(encoded)
  end
end
