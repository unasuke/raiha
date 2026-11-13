require "test_helper"
require "raiha/tls/test"

class RaihaTLSCryptoECDHTest < Minitest::Test
  TLS = Raiha::TLS
  ECDH = TLS::Crypto::ECDH
  RFC8448 = TLS::Test::RFC8448

  # RFC 8448 section 3: the client's X25519 key and the server's share give
  # the handshake IKM.
  def test_rfc8448_x25519
    key = ECDH.private_key(:x25519, RFC8448::Simple1RTT::CLIENT_X25519_PRIVATE_KEY)
    assert_equal_bin RFC8448::Simple1RTT::CLIENT_X25519_PUBLIC_KEY, ECDH.public_bytes(:x25519, key)
    assert_equal_bin RFC8448::Simple1RTT::HANDSHAKE_IKM, ECDH.derive(:x25519, key, RFC8448::Simple1RTT::SERVER_X25519_PUBLIC_KEY)
  end

  # RFC 8448 section 5: the client's second key share is on P-256.
  def test_rfc8448_secp256r1_public_key
    scalar = ["ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39"].pack("H*")
    key = ECDH.private_key(:secp256r1, scalar)
    key_share = RFC8448::HelloRetryRequest::CLIENT_HELLO_2.byteslice(4..)
    public_bytes = ECDH.public_bytes(:secp256r1, key)
    assert_equal 65, public_bytes.bytesize
    assert_includes key_share, public_bytes
  end

  def test_both_sides_agree
    ECDH.groups.each do |group|
      a = ECDH.generate(group)
      b = ECDH.generate(group)
      secret = ECDH.derive(group, a, ECDH.public_bytes(group, b))
      assert_equal secret, ECDH.derive(group, b, ECDH.public_bytes(group, a)), group.to_s
    end
  end

  def test_public_key_lengths
    assert_equal 32, ECDH.public_bytes(:x25519, ECDH.generate(:x25519)).bytesize
    assert_equal 65, ECDH.public_bytes(:secp256r1, ECDH.generate(:secp256r1)).bytesize
    assert_equal 97, ECDH.public_bytes(:secp384r1, ECDH.generate(:secp384r1)).bytesize
  end

  def test_invalid_x25519_peer_keys
    key = ECDH.generate(:x25519)
    assert_nil ECDH.derive(:x25519, key, "\x09".b * 31)
    # u = 0 gives the all-zero shared secret.
    assert_nil ECDH.derive(:x25519, key, "\x00".b * 32)
  end

  def test_invalid_nist_peer_keys
    key = ECDH.generate(:secp256r1)
    peer = ECDH.public_bytes(:secp256r1, ECDH.generate(:secp256r1))
    assert_nil ECDH.derive(:secp256r1, key, peer.byteslice(0, 64))
    compressed = ECDH.generate(:secp256r1).public_key.to_octet_string(:compressed)
    assert_nil ECDH.derive(:secp256r1, key, compressed)
    off_curve = "\x04".b + "\x01".b * 64
    assert_nil ECDH.derive(:secp256r1, key, off_curve)
    assert_nil ECDH.derive(:secp256r1, key, ECDH.public_bytes(:secp384r1, ECDH.generate(:secp384r1)))
  end

  def test_unsupported_group
    assert_raises(ArgumentError) { ECDH.generate(:x448) }
  end
end
