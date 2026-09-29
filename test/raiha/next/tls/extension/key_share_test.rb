require "raiha/next/test_helper"
require "raiha/next/tls/test"

class RaihaNextTLSExtensionKeyShareTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec
  KeyShare = Raiha::Next::TLS::Extension::KeyShare
  RFC8448 = Raiha::Next::TLS::Test::RFC8448::Simple1RTT

  def test_client_hello
    data = "\x00\x24\x00\x1d\x00\x20".b + RFC8448::CLIENT_X25519_PUBLIC_KEY
    ext = KeyShare::CH.parse(data)
    assert_equal [KeyShare::Entry.new(group: 0x001d, key_exchange: RFC8448::CLIENT_X25519_PUBLIC_KEY)], ext.client_shares
    assert_equal 51, ext.extension_type
    assert_equal_bin data, ext.encode
    assert Ractor.shareable?(ext)
  end

  def test_client_hello_may_offer_no_share
    ext = KeyShare::CH.parse("\x00\x00".b)
    assert_empty ext.client_shares
    assert_equal_bin "\x00\x00".b, ext.encode
  end

  def test_server_hello
    data = "\x00\x1d\x00\x20".b + RFC8448::SERVER_X25519_PUBLIC_KEY
    ext = KeyShare::SH.parse(data)
    assert_equal 0x001d, ext.server_share.group
    assert_equal RFC8448::SERVER_X25519_PUBLIC_KEY, ext.server_share.key_exchange
    assert_equal_bin data, ext.encode
  end

  def test_hello_retry_request_has_only_the_group
    ext = KeyShare::HRR.parse("\x00\x17".b)
    assert_equal 0x0017, ext.selected_group
    assert_equal_bin "\x00\x17".b, ext.encode
    assert_raises(Codec::TrailingData) { KeyShare::HRR.parse("\x00\x17\x00".b) }
  end

  def test_empty_key_exchange
    assert_raises(Codec::RangeViolation) { KeyShare::SH.parse("\x00\x1d\x00\x00".b) }
    assert_raises(Codec::EncodeError) { KeyShare::SH.new(server_share: KeyShare::Entry.new(group: 0x001d, key_exchange: "".b)).encode }
  end

  def test_inspect_masks_the_key
    entry = KeyShare::Entry.new(group: 0x001d, key_exchange: RFC8448::CLIENT_X25519_PUBLIC_KEY)
    refute_includes entry.inspect, RFC8448::CLIENT_X25519_PUBLIC_KEY.inspect[1..8]
    assert_includes entry.inspect, "key_exchange=[32 bytes]"
  end
end
