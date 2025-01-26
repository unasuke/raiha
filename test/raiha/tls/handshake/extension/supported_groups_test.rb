require "test_helper"
require "raiha/tls/handshake/extension"

class RaihaTLSHandshakeExtensionSupportedGroupsTest < Minitest::Test
  # https://tls13.xargs.org/#client-hello (without extension_type and extension_data length bytes)
  TLS13_XARGS_ORG_CLIENT_HELLO_SUPPORTED_GROUPS_DATA = [<<~DATA.gsub(/[[:space:]]/, '')].pack("H*")
    00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04
  DATA

  def test_extension_data
    supported_groups1 = Raiha::TLS::Handshake::Extension::SupportedGroups.new(on: :client_hello)
    supported_groups1.extension_data = TLS13_XARGS_ORG_CLIENT_HELLO_SUPPORTED_GROUPS_DATA
    expected_groups = ["x25519", "prime256v1", "x448", "secp521r1", "secp384r1", "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"]
    assert_equal expected_groups, supported_groups1.groups

    supported_groups2 = Raiha::TLS::Handshake::Extension::SupportedGroups.new(on: :client_hello)
    # private_use
    supported_groups2.extension_data = "\x00\x08\x01\xfc\x01\xff\xfe\x00\xfe\xff"
    assert_equal ["ffdhe_private_use", "ffdhe_private_use", "ecdhe_private_use", "ecdhe_private_use"], supported_groups2.groups
  end

  def test_serialize
    supported_groups1 = Raiha::TLS::Handshake::Extension::SupportedGroups.new(on: :client_hello)
    supported_groups1.groups = ["x25519"]
    assert_equal "\x00\x0a\x00\x04\x00\x02\x00\x1d", supported_groups1.serialize

    supported_groups2 = Raiha::TLS::Handshake::Extension::SupportedGroups.new(on: :client_hello)
    supported_groups2.groups = ["prime256v1", "secp384r1"]
    assert_equal "\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18", supported_groups2.serialize
  end
end
