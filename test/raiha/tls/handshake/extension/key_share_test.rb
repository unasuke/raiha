require "test_helper"
require "openssl"
require "raiha/tls/handshake/extension"

class RaihaTLSHandshakeExtensionKeyShareTest < Minitest::Test
  # https://tls13.xargs.org/#client-hello (without extension_type and extension_data length bytes)
  TLS13_XARGS_ORG_CLIENT_HELLO_KEY_SHARE_DATA = [<<~DATA.gsub(/[[:space:]]/, '')].pack("H*")
    00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df
    91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54
  DATA

  # https://tls13.xargs.org/#server-hello (without extension_type and extension_data length bytes)
  TLS13_XARGS_ORG_SERVER_HELLO_KEY_SHARE_DATA = [<<~DATA.gsub(/[[:space:]]/, '')].pack("H*")
    00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a
    f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15
  DATA

  def test_setup
    group_and_pkeys = [{ group: "prime256v1", pkey: OpenSSL::PKey::EC.generate("prime256v1") }]
    key_share = Raiha::TLS::Handshake::Extension::KeyShare.setup(group_and_pkeys)
    assert_equal "prime256v1", key_share.groups.first[:group]

    unsupported_group_and_pkeys = [{ group: "x25519", pkey: OpenSSL::PKey.generate_key("x25519") }]
    assert_raises do
      Raiha::TLS::Handshake::Extension::KeyShare.setup(unsupported_group_and_pkeys)
    end
  end

  def test_serialize_client_hello
    group_and_pkeys = [{ group: "prime256v1", pkey: OpenSSL::PKey::EC.generate("prime256v1") }]
    key_share = Raiha::TLS::Handshake::Extension::KeyShare.setup(group_and_pkeys)
    assert_equal String, key_share.serialize.class
    assert_equal "prime256v1", key_share.groups.first[:group]
  end

  def test_serialize_server_hello
    group_and_pkeys1 = [{ group: "prime256v1", pkey: OpenSSL::PKey::EC.generate("prime256v1") }]
    key_share1 = Raiha::TLS::Handshake::Extension::KeyShare.setup(group_and_pkeys1, on: :server_hello)
    assert_equal String, key_share1.serialize.class
    assert_equal "prime256v1", key_share1.groups.first[:group]

    group_and_pkeys2 = [
      { group: "prime256v1", pkey: OpenSSL::PKey::EC.generate("prime256v1") },
      { group: "secp384r1", pkey: OpenSSL::PKey::EC.generate("secp384r1") },
    ]
    key_share2 = Raiha::TLS::Handshake::Extension::KeyShare.setup(group_and_pkeys2, on: :server_hello)
    assert_raises do
      key_share2.serialize
    end
  end

  def test_extension_data
    key_share1 = Raiha::TLS::Handshake::Extension::KeyShare.new(on: :client_hello)
    key_share1.extension_data = TLS13_XARGS_ORG_CLIENT_HELLO_KEY_SHARE_DATA
    assert_equal "x25519", key_share1.groups.first[:group]

    key_share2 = Raiha::TLS::Handshake::Extension::KeyShare.new(on: :server_hello)
    key_share2.extension_data = TLS13_XARGS_ORG_SERVER_HELLO_KEY_SHARE_DATA
    assert_equal "x25519", key_share2.groups.first[:group]
  end

  def test_deserialize
    group_and_pkeys = [{ group: "prime256v1", pkey: OpenSSL::PKey::EC.generate("prime256v1") }]
    key_share1 = Raiha::TLS::Handshake::Extension::KeyShare.setup(group_and_pkeys, on: :client_hello)
    deserialized1 = Raiha::TLS::Handshake::Extension.deserialize_extensions(key_share1.serialize, type: :client_hello)
    deserialized_key_share1 = deserialized1.first
    assert_equal 1, deserialized_key_share1.groups.length
    assert_equal "prime256v1", deserialized_key_share1.groups.first[:group]

    key_share2 = Raiha::TLS::Handshake::Extension::KeyShare.setup(group_and_pkeys, on: :server_hello)
    deserialized2 = Raiha::TLS::Handshake::Extension.deserialize_extensions(key_share2.serialize, type: :server_hello)
    deserialized_key_share2 = deserialized2.first
    assert_equal 1, deserialized_key_share2.groups.length
    assert_equal "prime256v1", deserialized_key_share2.groups.first[:group]
  end
end
