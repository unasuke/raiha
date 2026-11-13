require "test_helper"
require "raiha/tls/test"

class RaihaNextTLSClientHelloBuilderTest < Minitest::Test
  TLS = Raiha::TLS
  Builder = TLS::Handshake::ClientHelloBuilder
  Extension = TLS::Extension
  RFC8448 = TLS::Test::RFC8448

  def build(config = TLS::Config.deterministic, random: Random.new(42), server_name: "example.com", extensions: [])
    keyring = TLS::Keyring.client(config:, verifier: TLS::Verifier::None.new, random:)
    Builder.build(config:, keyring:, server_name:, extensions:)
  end

  def types(client_hello) = client_hello.extensions.map(&:extension_type)

  def test_fixed_order
    config = TLS::Config.deterministic(alpn: ["h3"], record_size_limit: 16385,
      extensions: [Extension::Opaque.new(type: 0xff01, data: "\x00".b), Extension::Opaque.new(type: 0x39, data: "tp".b)])
    client_hello = build(config).client_hello
    assert_equal [0, 43, 10, 51, 13, 50, 45, 16, 28, 0x39, 0xff01], types(client_hello)
    assert_equal [1], client_hello.extension(45).ke_modes
    assert_equal [0x1301, 0x1302, 0x1303], client_hello.cipher_suites
    assert_equal [0x001d, 0x0017, 0x0018], client_hello.extension(10).named_group_list
    assert_equal [0x001d], client_hello.extension(51).client_shares.map(&:group)
  end

  # A client that does not resume offers no PSK key exchange mode, so no
  # server issues it tickets.
  def test_no_psk_key_exchange_modes_without_resumption
    refute_includes types(build(TLS::Config.deterministic(resumption: false)).client_hello), 45
  end

  # The random is drawn before anything else, so injecting the random
  # source reproduces it.
  def test_random_comes_first
    client_hello = build(random: Random.new(7)).client_hello
    assert_equal Random.new(7).bytes(32), client_hello.random
  end

  def test_round_trip_and_validate
    configs = [
      TLS::Config.deterministic, TLS::Config.client(trust_anchors: []),
      TLS::Config.client(alpn: %w[h3 h2], profile: TLS::Profile::QUIC),
      TLS::Config.client(groups: %i[secp384r1 x25519], signature_algorithms_cert: TLS::Config::DEFAULT_SIGNATURE_ALGORITHMS)
    ]
    configs.each do |config|
      client_hello = build(config, extensions: [Extension::Opaque.new(type: 0x39, data: "tp".b)]).client_hello
      parsed = TLS::Handshake.parse(client_hello.encode, registry: config.registry)
      assert_equal client_hello, parsed
      assert_nil parsed.validate
    end
  end

  def test_no_server_name_for_an_address
    refute_includes types(build(server_name: nil).client_hello), 0
  end

  # RFC 9001 forbids the middlebox compatibility mode in QUIC.
  def test_legacy_session_id_follows_the_profile
    assert_equal 32, build(TLS::Config.deterministic).client_hello.legacy_session_id.bytesize
    assert_equal "", build(TLS::Config.deterministic(profile: TLS::Profile::QUIC)).client_hello.legacy_session_id
  end

  def test_signature_algorithms_cert_only_when_it_differs
    same = TLS::Config.deterministic(signature_algorithms_cert: TLS::Config::DEFAULT_SIGNATURE_ALGORITHMS)
    refute_includes types(build(same).client_hello), 50
  end

  def test_permutation_is_seeded_by_the_random
    config = TLS::Config.client(trust_anchors: [], grease: false)
    first = build(config, random: Random.new(1)).client_hello
    assert_equal types(first), types(build(config, random: Random.new(1)).client_hello)
    orders = (1..20).map { |seed| types(build(config, random: Random.new(seed)).client_hello) }
    assert_operator orders.uniq.size, :>, 1
    assert_equal [types(first).sort], orders.map(&:sort).uniq
  end

  def test_grease
    client_hello = build(TLS::Config.client(trust_anchors: [], permute_extensions: true)).client_hello
    first, last = client_hello.extensions.first, client_hello.extensions.last
    assert TLS::IANA.grease?(first.extension_type)
    assert TLS::IANA.grease?(last.extension_type)
    refute_equal first.extension_type, last.extension_type
    assert_equal ["", "\x00"], [first.encode, last.encode]
    assert TLS::IANA.grease?(client_hello.cipher_suites.first)
    assert TLS::IANA.grease?(client_hello.extension(43).versions.first)
    grease_group = client_hello.extension(10).named_group_list.first
    assert TLS::IANA.grease?(grease_group)
    assert_equal grease_group, client_hello.extension(51).client_shares.first.group
  end

  def hello_retry_request(group:, cookie: nil)
    extensions = [Extension::SupportedVersions::SH.new(selected_version: 0x0304)]
    extensions.unshift(Extension::KeyShare::HRR.new(selected_group: group)) if group
    extensions << Extension::Cookie.new(cookie:) if cookie
    TLS::Handshake::ServerHello.new(legacy_version: 0x0303, random: TLS::Handshake::ServerHello::HELLO_RETRY_REQUEST_RANDOM,
      legacy_session_id_echo: "".b, cipher_suite: 0x1301, legacy_compression_method: 0, extensions:)
  end

  # The second ClientHello is made from the first and the HelloRetryRequest
  # alone, never the Config.
  def test_retry_takes_only_the_two_hellos
    assert_equal [%i[req ch1], %i[req hrr]], Builder.method(:retry).parameters
  end

  def test_retry_changes_only_what_rfc_9846_allows
    ch1 = build(TLS::Config.client(trust_anchors: [], alpn: ["h3"])).client_hello
    share = Extension::KeyShare::Entry.new(group: 0x0017, key_exchange: "\x04".b + "\x01".b * 64)
    ch2 = Builder.retry(ch1, hello_retry_request(group: 0x0017, cookie: "c00k1e".b)) { |group| (group == 0x0017) ? share : flunk }
    assert_equal [ch1.random, ch1.legacy_session_id, ch1.cipher_suites], [ch2.random, ch2.legacy_session_id, ch2.cipher_suites]
    assert_equal types(ch1) + [44], types(ch2)
    assert_equal [share], ch2.extension(51).client_shares
    assert_equal "c00k1e", ch2.extension(44).cookie
    unchanged = ch1.extensions.reject { |ext| ext.extension_type == 51 }
    assert_equal unchanged, ch2.extensions.reject { |ext| [44, 51].include?(ext.extension_type) }
    assert_nil TLS::Handshake.parse(ch2.encode, registry: TLS::Extension::Registry::BUILTIN).validate
  end

  # Without a pre_shared_key or padding the cookie goes last; otherwise
  # right before the first of them. RFC 8448's resumed ClientHello ends in
  # padding and pre_shared_key.
  def test_retry_inserts_the_cookie_before_padding_and_pre_shared_key
    ch1 = TLS::Handshake.parse(RFC8448::Resumed0RTT::CLIENT_HELLO, registry: TLS::Extension::Registry::BUILTIN)
    share = Extension::KeyShare::Entry.new(group: 0x001d, key_exchange: "\x01".b * 32)
    ch2 = Builder.retry(ch1, hello_retry_request(group: 0x001d, cookie: "c".b)) { share }
    assert_equal [44, 21, 41], types(ch2).last(3)
    refute_includes types(ch2), Extension::EarlyData::TYPE
    assert_includes types(ch1), Extension::EarlyData::TYPE
  end

  def test_retry_for_a_cookie_only_keeps_the_key_share
    ch1 = build.client_hello
    ch2 = Builder.retry(ch1, hello_retry_request(group: nil, cookie: "c".b)) { flunk "no group was requested" }
    assert_equal ch1.extension(51), ch2.extension(51)
    assert_equal types(ch1) + [44], types(ch2)
  end

  def test_retry_without_a_cookie
    ch1 = build.client_hello
    share = Extension::KeyShare::Entry.new(group: 0x0017, key_exchange: "\x04".b + "\x01".b * 64)
    ch2 = Builder.retry(ch1, hello_retry_request(group: 0x0017)) { share }
    assert_equal types(ch1), types(ch2)
  end
end
