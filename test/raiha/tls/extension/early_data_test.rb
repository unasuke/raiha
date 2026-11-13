require "test_helper"
require "raiha/tls"

class RaihaTLSExtensionEarlyDataTest < Minitest::Test
  Codec = Raiha::TLS::Codec
  EarlyData = Raiha::TLS::Extension::EarlyData

  def test_client_hello_and_encrypted_extensions_are_empty
    [EarlyData::CH, EarlyData::EE].each do |klass|
      ext = klass.parse("".b)
      assert_equal 42, ext.extension_type
      assert_equal "".b, ext.encode
      assert_raises(Codec::TrailingData) { klass.parse("\x00".b) }
    end
  end

  # early_data from the RFC 8448 section 3 NewSessionTicket.
  def test_new_session_ticket
    ext = EarlyData::NST.parse("\x00\x00\x04\x00".b)
    assert_equal 1024, ext.max_early_data_size
    assert_equal_bin "\x00\x00\x04\x00".b, ext.encode
    assert_raises(Codec::Truncated) { EarlyData::NST.parse("\x00\x00\x04".b) }
  end
end
