require "test_helper"
require "raiha/tls/test"

class RaihaNextTLSTestRFC8448Test < Minitest::Test
  RFC8448 = Raiha::TLS::Test::RFC8448

  def test_not_loaded_by_the_tls_entry_point
    out = IO.popen([RbConfig.ruby, "-I", File.expand_path("../../../../lib", __dir__), "-e",
      'require "raiha/tls"; print Raiha::TLS.const_defined?(:Test, false)'], &:read)
    assert_equal "false", out
  end

  def test_values_are_frozen_binary_and_shareable
    [RFC8448::Simple1RTT, RFC8448::Resumed0RTT, RFC8448::HelloRetryRequest].each do |section|
      section.constants.each do |name|
        value = section.const_get(name)
        assert_equal Encoding::BINARY, value.encoding, "#{section}::#{name}"
        assert Ractor.shareable?(value), "#{section}::#{name}"
      end
    end
  end

  def test_handshake_messages_carry_their_own_length
    messages = [
      RFC8448::Simple1RTT::CLIENT_HELLO, RFC8448::Simple1RTT::SERVER_HELLO,
      RFC8448::Simple1RTT::ENCRYPTED_EXTENSIONS, RFC8448::Simple1RTT::CERTIFICATE,
      RFC8448::Simple1RTT::CERTIFICATE_VERIFY, RFC8448::Simple1RTT::SERVER_FINISHED,
      RFC8448::Simple1RTT::CLIENT_FINISHED, RFC8448::Simple1RTT::NEW_SESSION_TICKET,
      RFC8448::Resumed0RTT::CLIENT_HELLO, RFC8448::Resumed0RTT::SERVER_HELLO,
      RFC8448::HelloRetryRequest::CLIENT_HELLO_1, RFC8448::HelloRetryRequest::HELLO_RETRY_REQUEST,
      RFC8448::HelloRetryRequest::CLIENT_HELLO_2, RFC8448::HelloRetryRequest::SERVER_HELLO
    ]
    messages.each do |message|
      length = (message.getbyte(1) << 16) | (message.getbyte(2) << 8) | message.getbyte(3)
      assert_equal message.bytesize - 4, length
    end
  end

  def test_sizes_given_in_the_rfc
    assert_equal 196, RFC8448::Simple1RTT::CLIENT_HELLO.bytesize
    assert_equal 90, RFC8448::Simple1RTT::SERVER_HELLO.bytesize
    assert_equal 512, RFC8448::Resumed0RTT::CLIENT_HELLO.bytesize
    assert_equal 477, RFC8448::Resumed0RTT::CLIENT_HELLO_PREFIX.bytesize
    assert_equal 180, RFC8448::HelloRetryRequest::CLIENT_HELLO_1.bytesize
    assert_equal 176, RFC8448::HelloRetryRequest::HELLO_RETRY_REQUEST.bytesize
    assert_equal 512, RFC8448::HelloRetryRequest::CLIENT_HELLO_2.bytesize
    assert_equal 123, RFC8448::HelloRetryRequest::SERVER_HELLO.bytesize
  end

  def test_client_hello_random_is_the_random_field
    assert_equal RFC8448::Simple1RTT::CLIENT_HELLO_RANDOM, RFC8448::Simple1RTT::CLIENT_HELLO.byteslice(6, 32)
  end

  def test_client_hello_prefix_is_the_start_of_the_client_hello
    prefix = RFC8448::Resumed0RTT::CLIENT_HELLO_PREFIX
    assert_equal prefix, RFC8448::Resumed0RTT::CLIENT_HELLO.byteslice(0, prefix.bytesize)
  end
end
