require "test_helper"
require_relative "../../../../../lib/raiha/tls/handshake"

class RaihaTLSHandshakeExtensionCookieTest < Minitest::Test
  def test_serialize_and_deserialize
    cookie = Raiha::TLS::Handshake::Extension::Cookie.new(on: :client_hello)
    cookie.cookie = "test_cookie_data"

    serialized = cookie.serialize
    buf = StringIO.new(serialized)
    ext_type = buf.read(2).unpack1("n")
    ext_length = buf.read(2).unpack1("n")
    ext_data = buf.read(ext_length)

    assert_equal 44, ext_type

    deserialized = Raiha::TLS::Handshake::Extension::Cookie.new(on: :client_hello)
    deserialized.extension_data = ext_data
    assert_equal "test_cookie_data", deserialized.cookie
  end

  def test_roundtrip_binary_data
    cookie = Raiha::TLS::Handshake::Extension::Cookie.new(on: :server_hello)
    cookie.cookie = "\x01\x02\x03\x04\x05".b

    serialized = cookie.serialize
    buf = StringIO.new(serialized)
    buf.read(2) # type
    ext_length = buf.read(2).unpack1("n")
    ext_data = buf.read(ext_length)

    deserialized = Raiha::TLS::Handshake::Extension::Cookie.new(on: :server_hello)
    deserialized.extension_data = ext_data
    assert_equal "\x01\x02\x03\x04\x05".b, deserialized.cookie
  end
end
