require "test_helper"
require "raiha/tls"

# For every generated value v, parsing v.encode gives v back and finds no
# violation. This holds only while what `encode` refuses stays a subset of
# what `validate` reports, so a failure means one of the two has drifted.
#
# Values come from a hand-written generator over the combinations that
# occur in practice: a full handshake, resumption, 0-RTT, the second
# ClientHello after a HelloRetryRequest, a Chrome-like ClientHello, and the
# smallest valid messages. A failure message carries the seed and the
# iteration, and RAIHA_FUZZ_SEED replays a seed.
class RaihaNextTLSHandshakeRoundTripPropertyTest < Minitest::Test
  TLS = Raiha::TLS
  Handshake = TLS::Handshake
  Extension = TLS::Extension
  REGISTRY = Extension::Registry::BUILTIN

  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "20260930"))
  ITERATIONS = 100

  class Generator
    Ext = Raiha::TLS::Extension
    HS = Raiha::TLS::Handshake

    SUITES = [0x1301, 0x1302, 0x1303].freeze
    # Group and a plausible key_exchange length.
    GROUPS = { 0x001d => 32, 0x0017 => 65, 0x0018 => 97, 0x11ec => 1216, 0x0100 => 256 }.freeze
    SCHEMES = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0401, 0x0501, 0x0601].freeze
    GREASE = (0..15).map { |n| (n << 12) | 0x0a00 | (n << 4) | 0x0a }.freeze

    def initialize(rng)
      @rng = rng
    end

    def bytes(range) = @rng.bytes(pick(range))

    def pick(range) = range.is_a?(Integer) ? range : @rng.rand(range)

    def subset(list, min: 1) = list.sample(@rng.rand(min..list.size), random: @rng)

    def grease_pair = GREASE.sample(2, random: @rng)

    def entry(group) = Ext::KeyShare::Entry.new(group:, key_exchange: bytes(GROUPS.fetch(group, 1)))

    def server_name = Ext::ServerName::CH.new(host_name: "host#{@rng.rand(1000)}.example")

    def signature_algorithms = Ext::SignatureAlgorithms.new(supported_signature_algorithms: subset(SCHEMES))

    def versions = Ext::SupportedVersions::CH.new(versions: [0x0304, 0x0303].take(@rng.rand(1..2)))

    def pre_shared_key
      count = @rng.rand(1..3)
      identities = Array.new(count) { Ext::PreSharedKey::Identity.new(identity: bytes(1..200), obfuscated_ticket_age: @rng.rand(2**32)) }
      binders = Array.new(count) { bytes([32, 48].sample(random: @rng)) }
      Ext::PreSharedKey::CH.new(identities:, binders:)
    end

    def client_hello(extensions, session_id: bytes(0..32), suites: subset(SUITES))
      HS::ClientHello.new(legacy_version: 0x0303, random: bytes(32), legacy_session_id: session_id,
        cipher_suites: suites, legacy_compression_methods: [0], extensions:)
    end

    def server_hello(extensions, random: bytes(32))
      HS::ServerHello.new(legacy_version: 0x0303, random:, legacy_session_id_echo: bytes(0..32),
        cipher_suite: SUITES.sample(random: @rng), legacy_compression_method: 0,
        extensions: [Ext::SupportedVersions::SH.new(selected_version: 0x0304)] + extensions)
    end

    def encrypted_extensions(extensions) = HS::EncryptedExtensions.new(extensions:)

    def finished = HS::Finished.new(verify_data: bytes([32, 48].sample(random: @rng)))

    def full_handshake
      groups = subset(GROUPS.keys)
      shares = subset(groups)
      optional = [
        Ext::Alpn.new(protocol_name_list: subset(["h3", "h2", "http/1.1"])),
        Ext::RecordSizeLimit.new(record_size_limit: @rng.rand(64..16385)),
        Ext::SignatureAlgorithmsCert.new(supported_signature_algorithms: subset(SCHEMES)),
        Ext::CompressCertificate.new(algorithms: subset([1, 2, 3])),
        Ext::CertificateAuthorities.new(authorities: Array.new(@rng.rand(1..3)) { bytes(1..40) })
      ]
      ch = client_hello([server_name, versions, Ext::SupportedGroups.new(named_group_list: groups),
        Ext::KeyShare::CH.new(client_shares: shares.map { |g| entry(g) }), signature_algorithms] + subset(optional, min: 0))
      entries = Array.new(@rng.rand(1..3)) do |i|
        extensions = i.zero? ? subset([Ext::Opaque.new(type: 5, data: bytes(1..20)), Ext::Opaque.new(type: 18, data: bytes(0..20))], min: 0) : []
        HS::CertificateEntry.new(cert_data: bytes(1..300), extensions:)
      end
      [
        ch,
        server_hello([Ext::KeyShare::SH.new(server_share: entry(shares.sample(random: @rng)))]),
        encrypted_extensions(subset([Ext::ServerName::EE.new, Ext::Alpn.new(protocol_name_list: ["h3"]),
          Ext::SupportedGroups.new(named_group_list: groups), Ext::RecordSizeLimit.new(record_size_limit: 16385)], min: 0)),
        HS::CertificateRequest.new(certificate_request_context: "".b, extensions: [signature_algorithms]),
        HS::Certificate.new(certificate_request_context: "".b, certificate_list: entries),
        HS::CertificateVerify.new(algorithm: [0x0403, 0x0804, 0x0807].sample(random: @rng), signature: bytes(64..256)),
        finished,
        HS::NewSessionTicket.new(ticket_lifetime: @rng.rand(604_800), ticket_age_add: @rng.rand(2**32),
          ticket_nonce: bytes(0..8), ticket: bytes(1..300), extensions: subset([Ext::EarlyData::NST.new(max_early_data_size: @rng.rand(2**32))], min: 0)),
        HS::KeyUpdate.new(request_update: @rng.rand(0..1))
      ]
    end

    # psk_ke carries no key share; psk_dhe_ke carries one.
    def resumption(early_data: false)
      with_dhe = @rng.rand(2).zero?
      groups = subset(GROUPS.keys)
      extensions = [server_name, versions, Ext::PskKeyExchangeModes.new(ke_modes: with_dhe ? [1] : [0])]
      extensions += [Ext::SupportedGroups.new(named_group_list: groups), Ext::KeyShare::CH.new(client_shares: [entry(groups.first)])] if with_dhe
      extensions << signature_algorithms if @rng.rand(2).zero?
      extensions << Ext::EarlyData::CH.new if early_data
      sh_extensions = [Ext::PreSharedKey::SH.new(selected_identity: 0)]
      sh_extensions << Ext::KeyShare::SH.new(server_share: entry(groups.first)) if with_dhe
      messages = [
        client_hello(extensions.shuffle(random: @rng) + [pre_shared_key]),
        server_hello(sh_extensions),
        encrypted_extensions(early_data ? [Ext::EarlyData::EE.new] : []),
        finished
      ]
      messages << HS::EndOfEarlyData.new if early_data
      messages
    end

    def after_hello_retry_request
      groups = subset(GROUPS.keys, min: 2)
      selected = groups.last
      cookie = Ext::Cookie.new(cookie: bytes(1..200))
      common = [server_name, versions, Ext::SupportedGroups.new(named_group_list: groups), signature_algorithms]
      [
        client_hello(common + [Ext::KeyShare::CH.new(client_shares: [entry(groups.first)])]),
        server_hello([Ext::KeyShare::HRR.new(selected_group: selected), cookie],
          random: HS::ServerHello::HELLO_RETRY_REQUEST_RANDOM),
        client_hello(common + [Ext::KeyShare::CH.new(client_shares: [entry(selected)]), cookie]),
        server_hello([Ext::KeyShare::SH.new(server_share: entry(selected))])
      ]
    end

    # GREASE at both ends, in the suites, groups, key shares and versions, and
    # the extensions Chrome sends that this implementation does not know.
    def chrome_like
      grease_ext, grease_ext2 = grease_pair
      grease_group = GREASE.sample(random: @rng)
      groups = [grease_group, 0x11ec, 0x001d, 0x0017, 0x0018]
      shuffled = [
        server_name,
        Ext::Opaque.new(type: 23, data: "".b),
        Ext::Opaque.new(type: 0xff01, data: "\x00".b),
        Ext::SupportedGroups.new(named_group_list: groups),
        Ext::Opaque.new(type: 11, data: "\x01\x00".b),
        Ext::Opaque.new(type: 35, data: "".b),
        Ext::Alpn.new(protocol_name_list: ["h2", "http/1.1"]),
        Ext::Opaque.new(type: 5, data: "\x01\x00\x00\x00\x00".b),
        signature_algorithms,
        Ext::Opaque.new(type: 18, data: "".b),
        Ext::KeyShare::CH.new(client_shares: [Ext::KeyShare::Entry.new(group: grease_group, key_exchange: "\x00".b), entry(0x11ec), entry(0x001d)]),
        Ext::PskKeyExchangeModes.new(ke_modes: [1]),
        Ext::SupportedVersions::CH.new(versions: [GREASE.sample(random: @rng), 0x0304, 0x0303]),
        Ext::CompressCertificate.new(algorithms: [2]),
        Ext::Opaque.new(type: 17613, data: bytes(3..10)),
        Ext::Opaque.new(type: 0xfe0d, data: bytes(100..250))
      ].shuffle(random: @rng)
      extensions = [Ext::Opaque.new(type: grease_ext, data: "".b)] + shuffled + [Ext::Opaque.new(type: grease_ext2, data: "\x00".b)]
      extensions << Ext::Opaque.new(type: 21, data: "\x00".b * pick(1..200)) if @rng.rand(2).zero?
      [
        client_hello(extensions, session_id: bytes(32), suites: [GREASE.sample(random: @rng)] + SUITES),
        server_hello([Ext::KeyShare::SH.new(server_share: entry(0x11ec))])
      ]
    end

    def minimal
      group = GROUPS.keys.sample(random: @rng)
      [
        client_hello([Ext::SupportedVersions::CH.new(versions: [0x0304]), Ext::SupportedGroups.new(named_group_list: [group]),
          Ext::KeyShare::CH.new(client_shares: [entry(group)]), Ext::SignatureAlgorithms.new(supported_signature_algorithms: [0x0804])],
          session_id: "".b, suites: [0x1301]),
        server_hello([Ext::KeyShare::SH.new(server_share: entry(group))]),
        encrypted_extensions([]),
        HS::Certificate.new(certificate_request_context: "".b, certificate_list: [HS::CertificateEntry.new(cert_data: "c".b, extensions: [])]),
        HS::CertificateVerify.new(algorithm: 0x0804, signature: "".b),
        HS::Finished.new(verify_data: "".b),
        HS::NewSessionTicket.new(ticket_lifetime: 0, ticket_age_add: 0, ticket_nonce: "".b, ticket: "t".b, extensions: [])
      ]
    end
  end

  def check(kind, &generate)
    generator = Generator.new(Random.new(SEED))
    ITERATIONS.times do |i|
      generate.call(generator).each do |message|
        where = "#{kind} seed=#{SEED} iteration=#{i} #{message.class.name.split("::").last}"
        parsed =
          begin
            Handshake.parse(message.encode, registry: REGISTRY)
          rescue TLS::Codec::Malformed, TLS::Codec::EncodeError => e
            flunk "#{where}: #{e.class}: #{e.message}"
          end
        assert_equal message, parsed, where
        assert_nil parsed.validate, where
      end
    end
  end

  def test_full_handshake = check(:full_handshake, &:full_handshake)

  def test_resumption = check(:resumption, &:resumption)

  def test_zero_rtt = check(:zero_rtt) { |generator| generator.resumption(early_data: true) }

  def test_after_hello_retry_request = check(:after_hello_retry_request, &:after_hello_retry_request)

  def test_chrome_like = check(:chrome_like, &:chrome_like)

  def test_minimal = check(:minimal, &:minimal)
end
