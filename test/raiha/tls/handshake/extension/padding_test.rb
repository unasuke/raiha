require "test_helper"
require "raiha/tls/handshake/extension/padding"

class RaihaTLSHandshakeExtensionPaddingTest < Minitest::Test
  def test_serialize
    zero_padding = Raiha::TLS::Handshake::Extension::Padding.new(on: :client_hello)
    zero_padding.length = 0
    zero_padding.extension_data = ""
    assert_equal zero_padding.serialize, "\x00\x15\x00\x00"

    one_padding = Raiha::TLS::Handshake::Extension::Padding.new(on: :client_hello)
    one_padding.length = 1
    one_padding.extension_data = "\x00"
    assert_equal one_padding.serialize, "\x00\x15\x00\x01\x00"
  end

  def test_generate_padding_with_length
    zero_padding = Raiha::TLS::Handshake::Extension::Padding.generate_padding_with_length(0)
    assert_equal zero_padding.serialize, "\x00\x15\x00\x00"

    one_padding = Raiha::TLS::Handshake::Extension::Padding.generate_padding_with_length(1)
    assert_equal one_padding.serialize, "\x00\x15\x00\x01\x00"
  end
end
