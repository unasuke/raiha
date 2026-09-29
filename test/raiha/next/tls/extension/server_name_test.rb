require "raiha/next/test_helper"
require "raiha/next/tls"

class RaihaNextTLSExtensionServerNameTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec
  ServerName = Raiha::Next::TLS::Extension::ServerName

  # server_name from the RFC 8448 section 3 ClientHello.
  RFC8448_CH = ["0009000006736572766572"].pack("H*")

  def test_parse_client_hello
    ext = ServerName::CH.parse(RFC8448_CH)
    assert_equal "server", ext.host_name
    assert_equal 0, ext.extension_type
    assert Ractor.shareable?(ext)
  end

  def test_encode_client_hello
    assert_equal_bin RFC8448_CH, ServerName::CH.new(host_name: "server").encode
  end

  def test_unknown_name_type
    assert_raises(Codec::Malformed) { ServerName::CH.parse(["0009010006736572766572"].pack("H*")) }
  end

  def test_more_than_one_name
    two_names = ["0008" "00000161" "00000162"].pack("H*")
    assert_raises(Codec::TrailingData) { ServerName::CH.parse(two_names) }
  end

  def test_empty_list_and_empty_name
    assert_raises(Codec::RangeViolation) { ServerName::CH.parse(["0000"].pack("H*")) }
    assert_raises(Codec::RangeViolation) { ServerName::CH.parse(["0003000000"].pack("H*")) }
    assert_raises(Codec::EncodeError) { ServerName::CH.new(host_name: "").encode }
  end

  def test_encrypted_extensions_is_empty
    ext = ServerName::EE.parse("".b)
    assert_equal 0, ext.extension_type
    assert_equal "".b, ext.encode
    assert_raises(Codec::TrailingData) { ServerName::EE.parse("\x00".b) }
  end
end
