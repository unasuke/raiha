require "test_helper"
require_relative "../../../../../lib/raiha/tls/handshake"

class RaihaTLSHandshakeExtensionEarlyDataTest < Minitest::Test
  def test_serialize_client_hello_empty
    ext = Raiha::TLS::Handshake::Extension::EarlyData.new(on: :client_hello)
    serialized = ext.serialize

    assert_equal [42, 0].pack("nn"), serialized
  end

  def test_serialize_new_session_ticket
    ext = Raiha::TLS::Handshake::Extension::EarlyData.new(on: :client_hello)
    ext.context = :new_session_ticket
    ext.max_early_data_size = 16384

    serialized = ext.serialize
    buf = StringIO.new(serialized)
    ext_type = buf.read(2).unpack1("n")
    ext_length = buf.read(2).unpack1("n")
    ext_data = buf.read(ext_length)

    assert_equal 42, ext_type
    assert_equal 4, ext_length
    assert_equal 16384, ext_data.unpack1("N")
  end

  def test_deserialize_new_session_ticket
    ext = Raiha::TLS::Handshake::Extension::EarlyData.new(on: :client_hello)
    ext.extension_data = [16384].pack("N")

    assert_equal :new_session_ticket, ext.context
    assert_equal 16384, ext.max_early_data_size
  end

  def test_deserialize_empty
    ext = Raiha::TLS::Handshake::Extension::EarlyData.new(on: :client_hello)
    ext.extension_data = ""

    assert_nil ext.context
    assert_nil ext.max_early_data_size
  end
end
