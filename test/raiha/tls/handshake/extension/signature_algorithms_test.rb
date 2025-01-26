require "test_helper"
require "raiha/tls/handshake/extension"

class RaihaTLSHandshakeExtensionSignatureAlgorithmsTest < Minitest::Test
  # https://tls13.xargs.org/#client-hello (without extension_type and extension_data length bytes)
  TLS13_XARGS_ORG_CLIENT_HELLO_SIGNATURE_ALGORITHMS_DATA = [<<~DATA.gsub(/[[:space:]]/, '')].pack("H*")
    00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01
  DATA

  def test_extension_data
    ext = Raiha::TLS::Handshake::Extension::SignatureAlgorithms.new(on: :client_hello)
    ext.extension_data = TLS13_XARGS_ORG_CLIENT_HELLO_SIGNATURE_ALGORITHMS_DATA
    expected_signature_algorithms = %w(
      ecdsa_secp256r1_sha256
      ecdsa_secp384r1_sha384
      ecdsa_secp521r1_sha512
      ed25519
      ed448
      rsa_pss_pss_sha256
      rsa_pss_pss_sha384
      rsa_pss_pss_sha512
      rsa_pss_rsae_sha256
      rsa_pss_rsae_sha384
      rsa_pss_rsae_sha512
      rsa_pkcs1_sha256
      rsa_pkcs1_sha384
      rsa_pkcs1_sha512
    )
    assert_equal expected_signature_algorithms, ext.signature_schemes
  end

  def test_serialize
    ext = Raiha::TLS::Handshake::Extension::SignatureAlgorithms.new(on: :client_hello)
    ext.signature_schemes = ["ecdsa_secp256r1_sha256", "ed25519"]
    assert_equal "\x00\x0d\x00\x06\x00\x04\x04\x03\x08\x07", ext.serialize

    deserialized1 = Raiha::TLS::Handshake::Extension.deserialize_extensions(ext.serialize, type: :client_hello)
    assert_equal ["ecdsa_secp256r1_sha256", "ed25519"], deserialized1.first.signature_schemes
  end
end
