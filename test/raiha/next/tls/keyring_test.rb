require "raiha/next/test_helper"
require "raiha/next/support/test_pki"
require "raiha/next/tls/test"

class RaihaNextTLSKeyringTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Keyring = TLS::Keyring
  PKI = NextTestPKI

  def ca = @ca ||= PKI.ca

  def leaf = @leaf ||= PKI.leaf(ca)

  def identity(issued = leaf, chain: [issued.der, ca.der]) = Keyring::Identity.new(cert_der: chain, key_der: issued.key_der)

  def server_config(**options) = TLS::Config.server(**options)

  def client_config(**options) = TLS::Config.client(trust_anchors: [ca.der], **options)

  def test_server_parses_its_identities
    keyring = Keyring.server(config: server_config, identities: [identity])
    credential = keyring.credentials.first
    assert_equal [leaf.der, ca.der], credential.chain_der
    assert_equal leaf.der, credential.leaf.to_der
    assert_equal leaf.key.public_to_der, credential.key.public_to_der
    assert keyring.frozen?
    refute Ractor.shareable?(keyring)
  end

  def test_pem_is_accepted
    pem = Keyring::Identity.new(cert_der: [leaf.certificate.to_pem], key_der: leaf.key.private_to_pem)
    assert_equal leaf.der, Keyring.server(config: server_config, identities: [pem]).credentials.first.chain_der.first
  end

  def test_identity_errors
    other = PKI.leaf(ca, key: PKI.key(:other_leaf))
    mismatched = Keyring::Identity.new(cert_der: [leaf.der], key_der: other.key_der)
    assert_raises(ArgumentError) { Keyring.server(config: server_config, identities: [mismatched]) }
    assert_raises(ArgumentError) { Keyring.server(config: server_config, identities: [identity(chain: [])]) }
    assert_raises(ArgumentError) { Keyring.server(config: server_config, identities: [identity(chain: ["junk".b])]) }
    public_only = Keyring::Identity.new(cert_der: [leaf.der], key_der: leaf.key.public_to_der)
    assert_raises(ArgumentError) { Keyring.server(config: server_config, identities: [public_only]) }
    assert_raises(ArgumentError) { Keyring.server(config: server_config, identities: []) }
  end

  def test_roles_must_match
    assert_raises(ArgumentError) { Keyring.server(config: client_config, identities: [identity]) }
    assert_raises(ArgumentError) { Keyring.client(config: server_config) }
  end

  # A default verifier with no trust anchors would accept nobody.
  def test_default_verifier_needs_trust_anchors
    assert_raises(ArgumentError) { Keyring.client(config: TLS::Config.client) }
    assert_raises(ArgumentError) do
      Keyring.server(config: server_config(client_auth: :optional), identities: [identity])
    end
    Keyring.server(config: server_config(client_auth: :required, trust_anchors: [ca.der]), identities: [identity])
    Keyring.client(config: TLS::Config.client, verifier: TLS::Verifier::None.new)
  end

  def test_peer_verified
    assert Keyring.client(config: client_config).peer_verified?
    refute Keyring.client(config: client_config, verifier: TLS::Verifier::None.new).peer_verified?
  end

  def test_key_exchange_must_support_the_groups
    fixed = TLS::Test::FixedKEM.new({ x25519: "\x01".b * 32 })
    assert_raises(ArgumentError) { Keyring.client(config: client_config, key_exchange: fixed) }
    keyring = Keyring.client(config: client_config(groups: %i[x25519]), key_exchange: fixed)
    assert_same fixed, keyring.key_exchange
  end

  def test_random_is_injected
    keyring = Keyring.client(config: client_config, random: Random.new(42))
    assert_equal Random.new(42).bytes(32), keyring.random_bytes(32)
  end

  def test_inspect_hides_keys
    keyring = Keyring.server(config: server_config, identities: [identity])
    refute_match(/PKey|credentials/, keyring.inspect)
    assert_includes identity.inspect, "key_der=[#{leaf.key_der.bytesize} bytes]"
  end
end
