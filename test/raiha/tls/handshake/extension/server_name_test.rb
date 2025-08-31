require "test_helper"
require "raiha/tls/handshake/extension"

class RaihaTLSHandshakeExtensionServerNameTest < Minitest::Test
  TLS13_SERVER_NAME_EXTENSION_DATA_WWW_EXAMPLE_COM = [<<~DATA.gsub(/[[:space:]]/, '')].pack("H*")
    00 00 00 14 00 12 00 00 0f 77 77 77 2e 65 78 61
    6d 70 6c 65 2e 63 6f 6d
  DATA

  TLS13_SERVER_NAME_EXTENSION_DATA_GOOGLE_COM = [<<~DATA.gsub(/[[:space:]]/, '')].pack("H*")
    00 00 00 0f 00 0d 00 00 0a 67 6f 6f 67 6c 65 2e
    63 6f 6d
  DATA

  TLS13_SERVER_NAME_EXTENSION_DATA_EMPTY = [<<~DATA.gsub(/[[:space:]]/, '')].pack("H*")
    00 00 00 00
  DATA
  def test_serialize
    www_example_com = Raiha::TLS::Handshake::Extension::ServerName.new(on: :client_hello)
    www_example_com.server_name = "www.example.com"
    assert_equal TLS13_SERVER_NAME_EXTENSION_DATA_WWW_EXAMPLE_COM, www_example_com.serialize

    google_com = Raiha::TLS::Handshake::Extension::ServerName.new(on: :client_hello)
    google_com.server_name = "google.com"
    assert_equal TLS13_SERVER_NAME_EXTENSION_DATA_GOOGLE_COM, google_com.serialize

    empty = Raiha::TLS::Handshake::Extension::ServerName.new(on: :encrypted_extensions)
    assert_equal TLS13_SERVER_NAME_EXTENSION_DATA_EMPTY, empty.serialize
  end
end
