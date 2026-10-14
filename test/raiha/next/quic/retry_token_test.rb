require "raiha/next/test_helper"
require "raiha/next/quic"

# RFC 9000 "Address Validation Using Retry Packets".
class RaihaNextQUICRetryTokenTest < Minitest::Test
  RetryToken = Raiha::Next::QUIC::RetryToken

  KEY = ("k" * 32).b
  ADDRESS = ["192.0.2.1", 4433].freeze
  NOW = Time.at(1_800_000_000)

  def mint(odcid = "o".b * 8, key: KEY, address: ADDRESS, time: NOW)
    RetryToken.mint(key:, original_destination_connection_id: odcid, address:, time:)
  end

  def verify(token, key: KEY, address: ADDRESS, time: NOW) = RetryToken.verify(token, key:, address:, time:)

  def test_round_trip
    ["".b, "o".b * 8, "x".b * 20].each { |odcid| assert_equal odcid, verify(mint(odcid)) }
    assert_equal 0, mint.getbyte(0)
  end

  # Only from the same address, with the same key, before it expires.
  def test_bound_to_the_address_the_key_and_the_time
    token = mint
    assert_nil verify(token, address: ["192.0.2.1", 4434])
    assert_nil verify(token, address: ["192.0.2.2", 4433])
    assert_nil verify(token, key: ("j" * 32).b)
    assert_equal "o".b * 8, verify(token, time: NOW + RetryToken::LIFETIME)
    assert_nil verify(token, time: NOW + RetryToken::LIFETIME + 1)
  end

  def test_anything_else_is_nil
    token = mint
    assert_nil verify("".b)
    assert_nil verify(token.byteslice(0, RetryToken::OVERHEAD - 1))
    flipped = token.dup.tap { _1.setbyte(5, _1.getbyte(5) ^ 1) }
    assert_nil verify(flipped)
    # Another kind, with a MAC that matches it.
    other = "\x01".b + token.byteslice(1, token.bytesize - 33)
    other += Raiha::Next::QUIC::Crypto::Mac.digest(KEY, other + "192.0.2.1\0".b + [4433].pack("n"))
    assert_nil verify(other)
  end

  # A length that does not match the bytes there, with a valid MAC.
  def test_a_wrong_length
    body = [0, NOW.to_i + 10, 9].pack("CQ>C") + "o".b * 8
    token = body + Raiha::Next::QUIC::Crypto::Mac.digest(KEY, body + "192.0.2.1\0".b + [4433].pack("n"))
    assert_nil verify(token)
  end
end
