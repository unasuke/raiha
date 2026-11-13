require "test_helper"
require "raiha/tls"

class RaihaNextTLSKeyExchangeTest < Minitest::Test
  TLS = Raiha::TLS
  Provider = TLS::KeyExchange::OpenSSL

  def setup
    @provider = Provider.new
  end

  # X25519 comes first.
  def test_supported_groups
    assert_equal %i[x25519 secp256r1 secp384r1], @provider.supported_groups
  end

  # The client generates, the server encapsulates to the client's public key,
  # and the client decapsulates the server's ciphertext.
  def test_kem_round_trip
    @provider.supported_groups.each do |group|
      client = @provider.generate(group)
      ciphertext, server_secret = @provider.encapsulate(group, client.public_bytes)
      assert_equal server_secret, @provider.decapsulate(client, ciphertext), group.to_s
      refute_equal client.public_bytes, ciphertext
    end
  end

  def test_key_pairs_are_fresh
    refute_equal @provider.generate(:x25519).public_bytes, @provider.generate(:x25519).public_bytes
  end

  def test_invalid_peer_keys_give_nil
    assert_nil @provider.encapsulate(:x25519, "\x00".b * 32)
    assert_nil @provider.encapsulate(:secp256r1, "\x04".b + "\x01".b * 64)
    assert_nil @provider.decapsulate(@provider.generate(:x25519), "\x00".b * 31)
  end

  def test_unsupported_group
    assert_raises(ArgumentError) { @provider.generate(:x448) }
    assert_raises(ArgumentError) { @provider.encapsulate(:x448, "k".b) }
  end

  def test_inspect_hides_the_private_key
    key_pair = @provider.generate(:x25519)
    assert_includes key_pair.inspect, "private_key=[masked]"
  end
end
