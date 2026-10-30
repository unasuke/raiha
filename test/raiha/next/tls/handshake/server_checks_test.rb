require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# The server's checks of the state machine's table, row by row, PSK rows
# aside: the row's violation gives its alert and reason, and with an
# earlier row violated too, the earlier row wins.
class RaihaNextTLSServerChecksTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Extension = TLS::Extension
  Handshake = TLS::Handshake
  Pair = NextTLSPair
  NOW = Pair::NOW
  REGISTRY = Extension::Registry::BUILTIN
  QUIC_TP = Extension::Opaque.new(type: 0x39, data: "tp".b)

  def failure(machine) = machine.each_event.grep(TLS::Event::Failed).first&.then { |f| [f.alert, f.reason] }

  def parse(bytes) = Handshake.parse(bytes, registry: REGISTRY)

  def client_hello(**options)
    extensions = options.delete(:extensions) || []
    parse(Pair.client(config: Pair.client_config(**options), extensions:).outputs.first.bytes)
  end

  def without(ch, *types) = ch.with(extensions: ch.extensions.reject { |ext| types.include?(ext.extension_type) })

  def adding(ch, *extensions) = ch.with(extensions: ch.extensions + extensions)

  def serve(ch, **config_options)
    failure(Pair.server(ch.encode, config: Pair.server_config(**config_options)))
  end

  def quic(**options) = { profile: TLS::Profile::QUIC, alpn: ["h3"], **options }

  # Rows 1 to 10, 12 and 13 of the server's table.
  def test_client_hello_rows
    assert_equal [:missing_extension, :required_extension], serve(client_hello(**quic), **quic)
    assert_equal [:unsupported_extension, :forbidden_extension], serve(client_hello(extensions: [QUIC_TP]))
    assert_equal [:illegal_parameter, :nonempty_legacy_session_id],
      serve(client_hello(**quic, extensions: [QUIC_TP]).with(legacy_session_id: "\x01".b * 32), **quic)
    assert_equal [:missing_extension, :server_name], serve(without(client_hello, 0), require_server_name: true)
    assert_equal [:handshake_failure, :no_common_cipher_suite],
      serve(client_hello(cipher_suites: %i[TLS_CHACHA20_POLY1305_SHA256]), cipher_suites: %i[TLS_AES_128_GCM_SHA256])
    assert_equal [:insufficient_security, :psk_dhe_ke_not_offered], serve(psk_only(ke_modes: [0]))
    assert_equal [:handshake_failure, :no_common_group], serve(client_hello(groups: %i[secp384r1]), groups: %i[x25519])
    assert_equal [:no_application_protocol, :no_common_application_protocol], serve(client_hello(alpn: ["h2"]), alpn: ["h3"])
    assert_equal [:no_application_protocol, :application_protocol_required],
      serve(client_hello(profile: TLS::Profile::QUIC, extensions: [QUIC_TP]), **quic)
    assert_equal [:illegal_parameter, :invalid_key_share], serve(zero_key_share(client_hello))
    assert_equal [:missing_extension, :signature_algorithms], serve(psk_only(ke_modes: [1], groups: true))
    assert_equal [:handshake_failure, :no_usable_certificate], serve(client_hello(signature_algorithms: %i[ed25519]))
  end

  def test_client_hello_rows_in_order
    # 1 before 3.
    assert_equal [:missing_extension, :required_extension],
      serve(client_hello(**quic).with(legacy_session_id: "\x01".b * 32), **quic)
    # 4 before 5.
    assert_equal [:missing_extension, :server_name],
      serve(without(client_hello(cipher_suites: %i[TLS_CHACHA20_POLY1305_SHA256]), 0),
        cipher_suites: %i[TLS_AES_128_GCM_SHA256], require_server_name: true)
    # 5 before 7.
    assert_equal [:handshake_failure, :no_common_cipher_suite],
      serve(client_hello(cipher_suites: %i[TLS_CHACHA20_POLY1305_SHA256], groups: %i[secp384r1]),
        cipher_suites: %i[TLS_AES_128_GCM_SHA256], groups: %i[x25519])
    # 7 before 8.
    assert_equal [:handshake_failure, :no_common_group], serve(client_hello(groups: %i[secp384r1], alpn: ["h2"]), groups: %i[x25519], alpn: ["h3"])
    # 8 before 10.
    assert_equal [:no_application_protocol, :no_common_application_protocol], serve(zero_key_share(client_hello(alpn: ["h2"])), alpn: ["h3"])
    # 10 before 13.
    assert_equal [:illegal_parameter, :invalid_key_share], serve(zero_key_share(client_hello(signature_algorithms: %i[ed25519])))
  end

  # A ClientHello offering a PSK and no signature_algorithms; with groups,
  # its key share too. No ticket can be decrypted, so the PSK is never
  # chosen and the server falls back to a certificate.
  def psk_only(ke_modes:, groups: false)
    ch = without(client_hello, 13, 50, 45)
    ch = without(ch, 10, 51) unless groups
    ch = adding(ch, Extension::PskKeyExchangeModes.new(ke_modes:))
    psk = Extension::PreSharedKey::CH.new(identities: [Extension::PreSharedKey::Identity.new(identity: "ticket".b, obfuscated_ticket_age: 0)],
      binders: ["\x00".b * 32])
    adding(ch, psk)
  end

  def zero_key_share(ch)
    ch.with(extensions: ch.extensions.map do |ext|
      next ext unless ext.extension_type == 51
      Extension::KeyShare::CH.new(client_shares: ext.client_shares.map { |s| s.with(key_exchange: "\x00".b * s.key_exchange.bytesize) })
    end)
  end

  # A server that sent a HelloRetryRequest, given a second ClientHello made
  # from the client's by `change`.
  def second_client_hello
    client = Pair.client
    server = Pair.server(client.outputs.first.bytes, config: Pair.server_config(groups: %i[secp256r1]))
    hrr = server.outputs.first
    client.receive(hrr.bytes, epoch: :initial, now: NOW)
    ch2 = yield(parse(client.outputs.first.bytes))
    server.receive(ch2.encode, epoch: :initial, now: NOW)
    failure(server)
  end

  # 0a to 0c: the second ClientHello may change only what RFC 9846 allows.
  def test_second_client_hello_rows
    assert_nil second_client_hello { |ch2| ch2 }
    assert_equal [:illegal_parameter, :client_hello_changed], second_client_hello { |ch2| ch2.with(random: "\x02".b * 32) }
    assert_equal [:illegal_parameter, :client_hello_changed],
      second_client_hello { |ch2| without(ch2, 0) }
    assert_equal [:illegal_parameter, :early_data_after_hello_retry_request],
      second_client_hello { |ch2| adding(ch2, Extension::EarlyData::CH.new) }
    assert_equal [:illegal_parameter, :key_share_not_requested_group], second_client_hello { |ch2|
      ch2.with(extensions: ch2.extensions.map { |e| e.extension_type == 51 ? Extension::KeyShare::CH.new(client_shares: []) : e })
    }
    # 0a before 0b.
    assert_equal [:illegal_parameter, :client_hello_changed],
      second_client_hello { |ch2| adding(ch2.with(random: "\x02".b * 32), Extension::EarlyData::CH.new) }
  end

  # The client's flight with one message replaced, against a server asking
  # for a certificate.
  # The server names no CAs, so a client sends whatever identity it has.
  def client_flight(mode: :required, identities: [Pair.client_identity])
    client = Pair.client(identities:)
    server = Pair.server(client.outputs.first.bytes, config: Pair.server_config(client_auth: mode, certificate_authorities: false))
    Pair.deliver(server.outputs, client)
    flight = client.outputs.grep(TLS::Output::Message).map { |m| parse(m.bytes) }
    flight = yield(flight) if block_given?
    flight.each { |message| server.receive(message.encode, epoch: :handshake, now: NOW) unless server.failed? }
    [server, failure(server)]
  end

  def replace(flight, type) = flight.map { |message| message.msg_type == type ? yield(message) : message }

  def test_client_certificate_rows
    assert_equal [:decode_error, :certificate_request_context],
      client_flight { |f| replace(f, 11) { |c| c.with(certificate_request_context: "\x01".b) } }.last
    assert_equal [:certificate_required, :certificate_required], client_flight(identities: []).last
    server, failed = client_flight(mode: :optional, identities: [])
    assert_nil failed
    assert server.complete?
    stranger = NextTestPKI.ca(name: "Stranger CA", key: NextTestPKI.key(:stranger_ca))
    leaf = NextTestPKI.leaf(stranger, names: [], purpose: "clientAuth")
    unknown = TLS::Keyring::Identity.new(cert_der: [leaf.der], key_der: leaf.key_der)
    %i[optional required].each do |mode|
      assert_equal [:unknown_ca, :certificate_rejected], client_flight(mode:, identities: [unknown]).last, mode
    end
  end

  def test_client_certificate_verify_and_finished_rows
    assert_equal [:decrypt_error, :bad_signature],
      client_flight { |f| replace(f, 15) { |cv| cv.with(signature: cv.signature.reverse) } }.last
    assert_equal [:illegal_parameter, :signature_algorithm],
      client_flight { |f| replace(f, 15) { |cv| cv.with(algorithm: 0x0804) } }.last
    assert_equal [:decrypt_error, :bad_finished],
      client_flight { |f| replace(f, 20) { |fin| fin.with(verify_data: fin.verify_data.reverse) } }.last
  end
end
