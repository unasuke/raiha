require "test_helper"
require "raiha/tls/handshake/extension"

class RaihaTLSHandshakeExtensionTest < Minitest::Test
  def test_serialize
    ext1 = Raiha::TLS::Handshake::Extension.new.tap do |ext|
      ext.extension_type = Raiha::TLS::Handshake::Extension::EXTENSION_TYPE[:supported_versions]
      ext.extension_data = "\x03\x04" # TLS13_SUPPORTED_VERSION
    end
    assert_equal "\x00\x2b\x00\x02\x03\x04", ext1.serialize

    ext2 = Raiha::TLS::Handshake::Extension.new.tap do |ext|
      ext.extension_type = Raiha::TLS::Handshake::Extension::EXTENSION_TYPE[:supported_groups]
      ext.extension_data = "\x03\x04"
    end
    assert_equal "\x00\x0a\x00\x02\x03\x04", ext2.serialize

    ext3 = Raiha::TLS::Handshake::Extension.new.tap do |ext|
      ext.extension_type = Raiha::TLS::Handshake::Extension::EXTENSION_TYPE[:signature_algorithms]
      ext.extension_data = "\x03\x04"
    end
    assert_equal "\x00\x0d\x00\x02\x03\x04", ext3.serialize
  end

  def test_deserialize_extensions
    client_hello_exts = "\x00\x2b\x00\x03\x02\x03\x04\x00\x0a\x00\x04\x00\x02\x00\x17\x00\x0d\x00\x04\x00\x02\x08\x04"
    extensions = Raiha::TLS::Handshake::Extension.deserialize_extensions(client_hello_exts, type: :client_hello)
    assert_equal Raiha::TLS::Handshake::Extension::SupportedVersions, extensions[0].class
    assert_equal_bin "\x02\x03\x04", extensions[0].extension_data
    assert_equal Raiha::TLS::Handshake::Extension::SupportedGroups, extensions[1].class
    assert_equal_bin "\x00\x02\x00\x17", extensions[1].extension_data
    assert_equal ["prime256v1"], extensions[1].groups
    assert_equal Raiha::TLS::Handshake::Extension::SignatureAlgorithms, extensions[2].class
    assert_equal_bin "\x00\x02\x08\x04", extensions[2].extension_data
    assert_equal ["rsa_pss_rsae_sha256"], extensions[2].signature_schemes

    # @see https://tls13.xargs.org/#server-hello
    server_hello_exts = "\x00\x2b\x00\x02\x03\x04\x00\x33\x00\x24\x00\x1d\x00\x20\x9f\xd7\xad\x6d\xcf\xf4\x29\x8d\xd3" +
      "\xf9\x6d\x5b\x1b\x2a\xf9\x10\xa0\x53\x5b\x14\x88\xd7\xf8\xfa\xbb\x34\x9a\x98\x28\x80\xb6\x15"
    extensions = Raiha::TLS::Handshake::Extension.deserialize_extensions(server_hello_exts, type: :server_hello)
    assert_equal 2, extensions.length
    assert_equal Raiha::TLS::Handshake::Extension::SupportedVersions, extensions[0].class
    assert_equal_bin "\x03\x04", extensions[0].extension_data
    assert_equal Raiha::TLS::Handshake::Extension::KeyShare, extensions[1].class
    assert_equal "x25519", extensions[1].groups.first[:group]
  end
end
