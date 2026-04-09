require "test_helper"
require_relative "../../../../../lib/raiha/tls/handshake"

class RaihaTLSHandshakeExtensionPskKeyExchangeModesTest < Minitest::Test
  def test_serialize_and_deserialize
    ext = Raiha::TLS::Handshake::Extension::PskKeyExchangeModes.new(on: :client_hello)
    ext.modes = [:psk_dhe_ke]

    serialized = ext.serialize
    buf = StringIO.new(serialized)
    ext_type = buf.read(2).unpack1("n")
    ext_length = buf.read(2).unpack1("n")
    ext_data = buf.read(ext_length)

    assert_equal 45, ext_type

    deserialized = Raiha::TLS::Handshake::Extension::PskKeyExchangeModes.new(on: :client_hello)
    deserialized.extension_data = ext_data
    assert_equal [:psk_dhe_ke], deserialized.modes
  end

  def test_multiple_modes
    ext = Raiha::TLS::Handshake::Extension::PskKeyExchangeModes.new(on: :client_hello)
    ext.modes = [:psk_ke, :psk_dhe_ke]

    serialized = ext.serialize
    buf = StringIO.new(serialized)
    buf.read(2) # type
    ext_length = buf.read(2).unpack1("n")
    ext_data = buf.read(ext_length)

    deserialized = Raiha::TLS::Handshake::Extension::PskKeyExchangeModes.new(on: :client_hello)
    deserialized.extension_data = ext_data
    assert_equal [:psk_ke, :psk_dhe_ke], deserialized.modes
  end
end
