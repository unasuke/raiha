require "test_helper"
require "raiha/tls/test"

class RaihaTLSHandshakeClientHelloTest < Minitest::Test
  TLS = Raiha::TLS
  ClientHello = TLS::Handshake::ClientHello
  Extension = TLS::Extension
  RFC8448 = TLS::Test::RFC8448
  REGISTRY = Extension::Registry::BUILTIN

  def parse(bytes) = TLS::Handshake.parse(bytes, registry: REGISTRY)

  def test_parse_rfc8448_simple_1rtt
    ch = parse(RFC8448::Simple1RTT::CLIENT_HELLO)
    assert_instance_of ClientHello, ch
    assert_equal 1, ch.msg_type
    assert_equal 0x0303, ch.legacy_version
    assert_equal RFC8448::Simple1RTT::CLIENT_HELLO_RANDOM, ch.random
    assert_equal "".b, ch.legacy_session_id
    assert_equal [0x1301, 0x1303, 0x1302], ch.cipher_suites
    assert_equal [0], ch.legacy_compression_methods
    assert_equal [0, 0xff01, 10, 35, 51, 43, 13, 45, 28], ch.extensions.map(&:extension_type)
    assert_equal [0x0304], ch.extension(43).versions
    assert_nil ch.extension(41)
  end

  # Appendix B 1: parsing a ClientHello and encoding it gives the same bytes.
  def test_encode_restores_every_rfc8448_client_hello
    [
      RFC8448::Simple1RTT::CLIENT_HELLO,
      RFC8448::Resumed0RTT::CLIENT_HELLO,
      RFC8448::HelloRetryRequest::CLIENT_HELLO_1,
      RFC8448::HelloRetryRequest::CLIENT_HELLO_2
    ].each do |bytes|
      assert_equal_bin bytes, parse(bytes).encode
    end
  end

  def test_parsed_client_hello_is_shareable
    assert Ractor.shareable?(parse(RFC8448::Resumed0RTT::CLIENT_HELLO))
  end

  # Appendix B 2: cutting the binders off the end gives RFC 8448's
  # "ClientHello prefix".
  def test_truncated_client_hello_is_the_rfc8448_prefix
    ch = parse(RFC8448::Resumed0RTT::CLIENT_HELLO)
    assert_equal 35, ch.binders_wire_length
    assert_equal_bin RFC8448::Resumed0RTT::CLIENT_HELLO_PREFIX, ch.encode_truncated
  end

  def test_placeholder_binders_leave_the_prefix_unchanged
    ch = parse(RFC8448::Resumed0RTT::CLIENT_HELLO)
    placeholder = ch.with_binders(["\x00".b * 32])
    assert_equal_bin ch.encode_truncated, placeholder.encode_truncated
    assert_equal_bin RFC8448::Resumed0RTT::CLIENT_HELLO, placeholder.with_binders(ch.extension(41).binders).encode
  end

  def test_with_binders_requires_the_same_lengths
    ch = parse(RFC8448::Resumed0RTT::CLIENT_HELLO)
    assert_raises(ArgumentError) { ch.with_binders(["\x00".b * 48]) }
    assert_raises(ArgumentError) { ch.with_binders([]) }
  end

  def test_with_binders_requires_pre_shared_key
    ch = parse(RFC8448::Simple1RTT::CLIENT_HELLO)
    assert_equal 0, ch.binders_wire_length
    assert_equal_bin ch.encode, ch.encode_truncated
    assert_raises(ArgumentError) { ch.with_binders(["\x00".b * 32]) }
  end

  def test_encode_rejects_pre_shared_key_that_is_not_last
    ch = parse(RFC8448::Resumed0RTT::CLIENT_HELLO)
    psk = ch.extension(41)
    moved = [psk] + ch.extensions.reject { |ext| ext.equal?(psk) }
    assert_raises(TLS::Codec::EncodeError) { ch.with(extensions: moved).encode }
  end

  def test_extensions_block_bounds
    ch = parse(RFC8448::Simple1RTT::CLIENT_HELLO)
    assert_raises(TLS::Codec::EncodeError) { ch.with(extensions: []).encode }
  end
end
