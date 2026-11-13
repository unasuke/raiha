require "test_helper"
require "raiha/tls/test"

class RaihaNextTLSHandshakeServerHelloTest < Minitest::Test
  TLS = Raiha::TLS
  ServerHello = TLS::Handshake::ServerHello
  Extension = TLS::Extension
  RFC8448 = TLS::Test::RFC8448
  REGISTRY = Extension::Registry::BUILTIN

  def parse(bytes) = TLS::Handshake.parse(bytes, registry: REGISTRY)

  def test_parse_rfc8448_simple_1rtt
    sh = parse(RFC8448::Simple1RTT::SERVER_HELLO)
    assert_instance_of ServerHello, sh
    assert_equal 2, sh.msg_type
    assert_equal 0x0303, sh.legacy_version
    assert_equal "".b, sh.legacy_session_id_echo
    assert_equal 0x1301, sh.cipher_suite
    assert_equal 0, sh.legacy_compression_method
    refute sh.hello_retry_request?
    assert_equal RFC8448::Simple1RTT::SERVER_X25519_PUBLIC_KEY, sh.extension(51).server_share.key_exchange
    assert_equal 0x0304, sh.extension(43).selected_version
  end

  def test_hello_retry_request_is_a_server_hello_with_a_fixed_random
    hrr = parse(RFC8448::HelloRetryRequest::HELLO_RETRY_REQUEST)
    assert_instance_of ServerHello, hrr
    assert hrr.hello_retry_request?
    assert_equal Extension::KeyShare::HRR.new(selected_group: 0x0017), hrr.extension(51)
    assert_instance_of Extension::Cookie, hrr.extension(44)
    assert_instance_of Extension::SupportedVersions::SH, hrr.extension(43)
  end

  def test_encode_restores_every_rfc8448_server_hello
    [
      RFC8448::Simple1RTT::SERVER_HELLO,
      RFC8448::Resumed0RTT::SERVER_HELLO,
      RFC8448::HelloRetryRequest::HELLO_RETRY_REQUEST,
      RFC8448::HelloRetryRequest::SERVER_HELLO
    ].each do |bytes|
      sh = parse(bytes)
      assert_equal_bin bytes, sh.encode
      assert Ractor.shareable?(sh)
    end
  end

  def test_cookie_is_allowed_only_in_a_hello_retry_request
    sh = parse(RFC8448::Simple1RTT::SERVER_HELLO)
    with_cookie = sh.with(extensions: sh.extensions + [Extension::Cookie.new(cookie: "c".b)])
    assert_raises(TLS::Codec::IllegalPlacement) { parse(with_cookie.encode) }

    hrr = with_cookie.with(random: ServerHello::HELLO_RETRY_REQUEST_RANDOM,
      extensions: [Extension::SupportedVersions::SH.new(selected_version: 0x0304), Extension::Cookie.new(cookie: "c".b)])
    assert_equal hrr, parse(hrr.encode)
  end

  def test_hello_retry_request_key_share_holds_only_a_group
    hrr = parse(RFC8448::HelloRetryRequest::HELLO_RETRY_REQUEST)
    sh_shaped = hrr.with(random: RFC8448::Simple1RTT::SERVER_HELLO.byteslice(6, 32),
      extensions: [Extension::KeyShare::HRR.new(selected_group: 0x0017)])
    assert_raises(TLS::Codec::Truncated) { parse(sh_shaped.encode) }
  end
end
