require "test_helper"
require "raiha/tls/test"

class RaihaNextTLSTestFixedKEMTest < Minitest::Test
  TLS = Raiha::Next::TLS
  FixedKEM = TLS::Test::FixedKEM
  RFC8448 = TLS::Test::RFC8448

  def test_rfc8448_x25519_on_both_sides
    s = RFC8448::Simple1RTT
    client = FixedKEM.new(x25519: s::CLIENT_X25519_PRIVATE_KEY)
    server = FixedKEM.new(x25519: s::SERVER_X25519_PRIVATE_KEY)
    key_pair = client.generate(:x25519)
    assert_equal_bin s::CLIENT_X25519_PUBLIC_KEY, key_pair.public_bytes
    ciphertext, server_secret = server.encapsulate(:x25519, key_pair.public_bytes)
    assert_equal_bin s::SERVER_X25519_PUBLIC_KEY, ciphertext
    assert_equal_bin s::HANDSHAKE_IKM, server_secret
    assert_equal_bin s::HANDSHAKE_IKM, client.decapsulate(key_pair, ciphertext)
  end

  # Section 5: the client's first share is X25519, the second, after the
  # HelloRetryRequest, P-256.
  def test_rfc8448_hello_retry_request_keys
    h = RFC8448::HelloRetryRequest
    client = FixedKEM.new(x25519: h::CLIENT_X25519_PRIVATE_KEY, secp256r1: h::CLIENT_SECP256R1_PRIVATE_KEY)
    server = FixedKEM.new(secp256r1: h::SERVER_SECP256R1_PRIVATE_KEY)
    assert_equal %i[x25519 secp256r1], client.supported_groups
    assert_equal_bin h::CLIENT_X25519_PUBLIC_KEY, client.generate(:x25519).public_bytes
    key_pair = client.generate(:secp256r1)
    assert_equal_bin h::CLIENT_SECP256R1_PUBLIC_KEY, key_pair.public_bytes
    ciphertext, server_secret = server.encapsulate(:secp256r1, key_pair.public_bytes)
    assert_equal_bin h::SERVER_SECP256R1_PUBLIC_KEY, ciphertext
    assert_equal_bin h::HANDSHAKE_IKM, server_secret
    assert_equal_bin h::HANDSHAKE_IKM, client.decapsulate(key_pair, ciphertext)
  end

  def test_group_without_a_fixed_key
    assert_raises(ArgumentError) { FixedKEM.new(x25519: "\x01".b * 32).generate(:secp256r1) }
  end

  def test_invalid_peer_key
    kem = FixedKEM.new(x25519: "\x01".b * 32)
    assert_nil kem.encapsulate(:x25519, "\x00".b * 32)
  end
end
