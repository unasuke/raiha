require "test_helper"
require_relative "../../../../../lib/raiha/tls/handshake"

class RaihaTLSHandshakeExtensionPreSharedKeyTest < Minitest::Test
  def test_server_hello_roundtrip
    ext = Raiha::TLS::Handshake::Extension::PreSharedKey.new(on: :server_hello)
    ext.selected_identity = 0

    serialized = ext.serialize
    buf = StringIO.new(serialized)
    ext_type = buf.read(2).unpack1("n")
    ext_length = buf.read(2).unpack1("n")
    ext_data = buf.read(ext_length)

    assert_equal 41, ext_type

    deserialized = Raiha::TLS::Handshake::Extension::PreSharedKey.new(on: :server_hello)
    deserialized.extension_data = ext_data
    assert_equal 0, deserialized.selected_identity
  end

  def test_client_hello_roundtrip
    ext = Raiha::TLS::Handshake::Extension::PreSharedKey.new(on: :client_hello)
    ext.identities << Raiha::TLS::Handshake::Extension::PreSharedKey::PskIdentity.new("ticket_data", 12345)
    ext.binders << ("\x00" * 32).b

    serialized = ext.serialize
    buf = StringIO.new(serialized)
    ext_type = buf.read(2).unpack1("n")
    ext_length = buf.read(2).unpack1("n")
    ext_data = buf.read(ext_length)

    assert_equal 41, ext_type

    deserialized = Raiha::TLS::Handshake::Extension::PreSharedKey.new(on: :client_hello)
    deserialized.extension_data = ext_data

    assert_equal 1, deserialized.identities.length
    assert_equal "ticket_data", deserialized.identities.first.identity
    assert_equal 12345, deserialized.identities.first.obfuscated_ticket_age
    assert_equal 1, deserialized.binders.length
    assert_equal ("\x00" * 32).b, deserialized.binders.first
  end
end
