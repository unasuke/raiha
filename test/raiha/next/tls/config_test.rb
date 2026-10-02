require "raiha/next/test_helper"
require "raiha/next/tls"

class RaihaNextTLSConfigTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Config = TLS::Config
  Opaque = TLS::Extension::Opaque

  # A typed extension value no registry knows.
  Unregistered = Data.define(:value) do
    def extension_type = 0x1234
    def encode = value
  end

  def test_defaults
    config = Config.client
    assert_equal :client, config.role
    assert_same TLS::Profile::TCP, config.profile
    assert_equal [0x1301, 0x1302, 0x1303], config.cipher_suite_ids
    assert_equal [0x001d, 0x0017, 0x0018], config.group_ids
    assert config.signature_algorithm_ids.all? { |id| TLS::SignatureScheme.find(id).usable_in_certificate_verify? }
    assert_includes config.signature_algorithm_cert_ids, 0x0401
    assert config.permute_extensions
    assert config.grease
    assert_equal :none, Config.server.client_auth
  end

  def test_deterministic_turns_off_permutation_and_grease
    config = Config.deterministic(alpn: ["h3"])
    assert_equal [false, false, ["h3"]], [config.permute_extensions, config.grease, config.alpn]
  end

  def test_shareable_without_freezing_what_the_caller_passed
    alpn = ["h3".dup]
    extensions = [Opaque.new(type: 0xff01, data: "\x00".b)]
    config = Config.server(alpn:, extensions:)
    assert Ractor.shareable?(config)
    refute alpn.frozen?
    refute alpn.first.frozen?
  end

  def test_with_checks_again_and_keeps_the_role
    server = Config.server(alpn: ["h3"])
    changed = server.with(alpn: ["h2"], client_auth: :required)
    assert_equal [:server, ["h2"], :required], [changed.role, changed.alpn, changed.client_auth]
    assert Ractor.shareable?(changed)
    assert_equal ["h3"], server.alpn
    assert_raises(ArgumentError) { server.with(cipher_suites: []) }
  end

  def test_enumerated_settings_must_be_known_once
    assert_raises(ArgumentError) { Config.client(cipher_suites: []) }
    # Known to IANA but not implemented.
    assert_raises(ArgumentError) { Config.client(cipher_suites: %i[TLS_AES_128_CCM_SHA256]) }
    assert_raises(ArgumentError) { Config.client(cipher_suites: %i[TLS_AES_128_GCM_SHA256 TLS_AES_128_GCM_SHA256]) }
    assert_raises(ArgumentError) { Config.client(groups: %i[x25519 nonexistent]) }
    assert_raises(ArgumentError) { Config.client(signature_algorithms_cert: %i[rsa_pkcs1_md5]) }
  end

  # RSASSA-PKCS1-v1_5 and SHA-1 may sign certificates but never a
  # CertificateVerify.
  def test_signature_algorithms_must_be_usable_in_certificate_verify
    error = assert_raises(ArgumentError) { Config.client(signature_algorithms: %i[rsa_pss_rsae_sha256 rsa_pkcs1_sha256]) }
    assert_match(/rsa_pkcs1_sha256/, error.message)
    assert_raises(ArgumentError) { Config.client(signature_algorithms: %i[ecdsa_sha1]) }
    Config.client(signature_algorithms_cert: %i[rsa_pkcs1_sha256 rsa_pkcs1_sha1])
  end

  def test_alpn
    assert_raises(ArgumentError) { Config.client(alpn: [""]) }
    assert_raises(ArgumentError) { Config.client(alpn: ["x" * 256]) }
    assert_raises(ArgumentError) { Config.client(alpn: %w[h3 h3]) }
    assert_equal ["x" * 255], Config.client(alpn: ["x" * 255]).alpn
  end

  def test_extensions
    # One way to set each extension: these are built by the handshake.
    [0x00, 0x0a, 0x0d, 0x10, 0x1c, 0x29, 0x2b, 0x2c, 0x33].each do |type|
      assert_raises(ArgumentError, type.to_s) { Config.client(extensions: [Opaque.new(type:, data: "".b)]) }
    end
    assert_raises(ArgumentError) { Config.client(extensions: [Opaque.new(type: 0x0a0a, data: "".b)]) }
    assert_raises(ArgumentError) { Config.client(extensions: [Unregistered.new(value: "".b)]) }
    assert_raises(ArgumentError) do
      Config.client(extensions: [Opaque.new(type: 0x39, data: "a".b), Opaque.new(type: 0x39, data: "b".b)])
    end
    # Raw bytes of a type the registry does not know are fine.
    assert_equal 1, Config.client(extensions: [Opaque.new(type: 0x39, data: "".b)]).extensions.size
  end

  def test_a_proc_cannot_be_shared
    error = assert_raises(ArgumentError) { Config.client(extensions: [Opaque.new(type: 0xff01, data: -> { "".b })]) }
    assert_match(/Proc/, error.message)
  end

  def test_exporter_labels
    assert_equal ["x" * 249], Config.client(exporter_labels: ["x" * 249]).exporter_labels
    assert_raises(ArgumentError) { Config.client(exporter_labels: [""]) }
    assert_raises(ArgumentError) { Config.client(exporter_labels: ["x" * 250]) }
    assert_raises(ArgumentError) { Config.client(exporter_labels: %w[EXPORTER-a EXPORTER-a]) }
  end

  def test_record_size_limit
    assert_nil Config.client.record_size_limit
    assert_equal 64, Config.client(record_size_limit: 64).record_size_limit
    assert_equal 16385, Config.client(record_size_limit: 16385).record_size_limit
    assert_raises(ArgumentError) { Config.client(record_size_limit: 63) }
    assert_raises(ArgumentError) { Config.client(record_size_limit: 16386) }
  end

  def test_server_settings_on_a_client_raise
    assert_raises(ArgumentError) { Config.client(client_auth: :required) }
    assert_raises(ArgumentError) { Config.client(require_server_name: true) }
    assert_raises(ArgumentError) { Config.server(client_auth: :sometimes) }
  end

  def test_sizes_must_be_positive
    assert_raises(ArgumentError) { Config.client(max_handshake_message_size: 0) }
    assert_raises(ArgumentError) { Config.client(max_certificate_chain_length: -1) }
  end
end
