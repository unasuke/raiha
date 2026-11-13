require "test_helper"
require "support/test_pki"
require "raiha/tls/test"

class RaihaNextTLSKeyringTest < Minitest::Test
  TLS = Raiha::TLS
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
    random = Random.new(42)
    keyring = Keyring.client(config: client_config, random:)
    assert_equal Random.new(42).bytes(32), keyring.random_bytes(32)
    assert_same random, keyring.random
  end

  def test_inspect_hides_keys
    keyring = Keyring.server(config: server_config, identities: [identity])
    refute_match(/PKey|credentials/, keyring.inspect)
    assert_includes identity.inspect, "key_der=[#{leaf.key_der.bytesize} bytes]"
  end

  # A Keyring of the Config with other ticket keys shares what was parsed,
  # and a handshake takes it with that Config, not with the first.
  def test_with_ticket_keys
    config = server_config(ticket_key: "\x01".b * 32)
    keyring = Keyring.server(config:, identities: [identity])
    keys = TLS::TicketKeys.static(current: "\x02".b * 32)
    other = keyring.with_ticket_keys(keys)
    assert_same keys, other.config.ticket_keys
    assert_equal config.with(ticket_keys: keys).alpn, other.config.alpn
    assert_same config, keyring.config
    assert_same keyring.credentials, other.credentials
    assert_same keyring.verifier, other.verifier
    assert other.frozen?
    TLS::Handshake::Machine.server(config: other.config, keyring: other, now: Time.now)
    assert_raises(ArgumentError) { TLS::Handshake::Machine.server(config:, keyring: other, now: Time.now) }
  end
end

# Choosing an identity to answer with (RFC 9846 "Certificate Selection").
class RaihaNextTLSKeyringSelectionTest < Minitest::Test
  TLS = Raiha::TLS
  Keyring = TLS::Keyring
  PKI = NextTestPKI

  def ca = @ca ||= PKI.ca

  def identity(names: ["DNS:localhost"], key: PKI.key(:p256), issuer: ca)
    leaf = PKI.leaf(issuer, names:, key:)
    Keyring::Identity.new(cert_der: [leaf.der, issuer.der], key_der: leaf.key_der)
  end

  ECDSA = [0x0403].freeze
  PSS = [0x0804].freeze

  def server(identities)
    Keyring.server(config: TLS::Config.server, identities:)
  end

  def select(keyring, server_name: "localhost", signature_algorithms: ECDSA + PSS, signature_algorithms_cert: nil, certificate_authorities: nil)
    credential, scheme = keyring.server_credential(server_name:, signature_algorithms:, signature_algorithms_cert:, certificate_authorities:)
    [keyring.credentials.index(credential), scheme&.name]
  end

  def test_server_picks_a_key_the_client_can_verify
    keyring = server([identity(key: PKI.key(:rsa)), identity(key: PKI.key(:p256))])
    assert_equal [0, :rsa_pss_rsae_sha256], select(keyring)
    assert_equal [1, :ecdsa_secp256r1_sha256], select(keyring, signature_algorithms: ECDSA)
    assert_equal [nil, nil], select(keyring, signature_algorithms: [0x0807])
  end

  def test_server_prefers_a_valid_name_then_the_order
    keyring = server([identity(names: ["DNS:other.example"]), identity(names: ["DNS:localhost"], key: PKI.key(:second))])
    assert_equal [1, :ecdsa_secp256r1_sha256], select(keyring)
    assert_equal [0, :ecdsa_secp256r1_sha256], select(keyring, server_name: "nowhere.example")
    assert_equal [0, :ecdsa_secp256r1_sha256], select(keyring, server_name: nil)
  end

  def test_server_prefers_a_chain_the_client_accepts_and_a_named_ca
    other_ca = PKI.ca(name: "Other CA", key: PKI.key(:other_ca))
    keyring = server([identity, identity(issuer: other_ca, key: PKI.key(:third))])
    # Both chains are signed with ecdsa-with-SHA256; only the CA differs.
    assert_equal [1, :ecdsa_secp256r1_sha256], select(keyring, certificate_authorities: [other_ca.certificate.subject.to_der])
    assert_equal [0, :ecdsa_secp256r1_sha256], select(keyring, signature_algorithms_cert: [0x0804])
  end

  def test_client_answers_a_certificate_request
    keyring = Keyring.client(config: TLS::Config.client(trust_anchors: [ca.der]), identities: [identity(key: PKI.key(:rsa)), identity])
    credential, scheme = keyring.client_credential(signature_algorithms: ECDSA, certificate_authorities: nil)
    assert_equal [1, :ecdsa_secp256r1_sha256], [keyring.credentials.index(credential), scheme.name]
    assert_nil keyring.client_credential(signature_algorithms: [0x0807], certificate_authorities: nil)
    assert_nil keyring.client_credential(signature_algorithms: ECDSA, certificate_authorities: ["\x30\x00".b])
    credential, = keyring.client_credential(signature_algorithms: ECDSA, certificate_authorities: [ca.certificate.subject.to_der])
    assert_equal 1, keyring.credentials.index(credential)
  end

  def test_trust_anchor_subjects
    keyring = Keyring.client(config: TLS::Config.client(trust_anchors: [ca.der]))
    assert_equal [ca.certificate.subject.to_der], keyring.trust_anchor_subjects
  end
end
