require "raiha/next/test_helper"
require "raiha/next/tls/test"

class RaihaNextTLSExtensionPreSharedKeyTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec
  PreSharedKey = Raiha::Next::TLS::Extension::PreSharedKey
  RFC8448 = Raiha::Next::TLS::Test::RFC8448::Resumed0RTT

  # pre_shared_key is the last extension of the section 4 ClientHello, and its
  # extension_data is the last 221 bytes.
  CH_DATA = RFC8448::CLIENT_HELLO.byteslice(-221, 221)

  def test_client_hello
    ext = PreSharedKey::CH.parse(CH_DATA)
    assert_equal 1, ext.identities.size
    assert_equal 178, ext.identities.first.identity.bytesize
    assert_equal 0xfad6aacb, ext.identities.first.obfuscated_ticket_age
    assert_equal [32], ext.binders.map(&:bytesize)
    assert_equal 41, ext.extension_type
    assert_equal_bin CH_DATA, ext.encode
    assert Ractor.shareable?(ext)
  end

  def test_binder_bounds
    identities = "\x00\x07\x00\x01x\x00\x00\x00\x00".b
    assert_raises(Codec::RangeViolation) { PreSharedKey::CH.parse(identities + "\x00\x20\x1f".b + "\x00".b * 31) }
    ext = PreSharedKey::CH.new(identities: [PreSharedKey::Identity.new(identity: "x", obfuscated_ticket_age: 0)], binders: ["\x00".b * 31])
    assert_raises(Codec::EncodeError) { ext.encode }
  end

  def test_empty_identities
    assert_raises(Codec::RangeViolation) { PreSharedKey::CH.parse("\x00\x00\x00\x21\x20".b + "\x00".b * 32) }
  end

  def test_server_hello
    ext = PreSharedKey::SH.parse("\x00\x00".b)
    assert_equal 0, ext.selected_identity
    assert_equal_bin "\x00\x00".b, ext.encode
  end

  def test_inspect_masks_the_binders
    ext = PreSharedKey::CH.parse(CH_DATA)
    assert_includes ext.inspect, "binders=[[32 bytes]]"
    refute_includes ext.inspect, ext.binders.first.inspect[1..8]
  end
end
