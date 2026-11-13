require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# The client's checks of the state machine's table, row by row: the row's
# violation gives its alert and reason, and with the row before it violated
# too, the earlier row wins.
class RaihaNextTLSClientChecksTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Extension = TLS::Extension
  Handshake = TLS::Handshake
  Pair = NextTLSPair
  NOW = Pair::NOW
  REGISTRY = Extension::Registry::BUILTIN

  def failure(machine) = machine.each_event.grep(TLS::Event::Failed).first&.then { |f| [f.alert, f.reason] }

  def parse(bytes) = Handshake.parse(bytes, registry: REGISTRY)

  # A client that offered only TLS_AES_128_GCM_SHA256 and an x25519 share.
  def client(**options)
    machine = Pair.client(config: Pair.client_config(cipher_suites: %i[TLS_AES_128_GCM_SHA256], **options))
    [machine, parse(machine.outputs.first.bytes)]
  end

  def share(group = 0x001d)
    key_pair = TLS::KeyExchange::OpenSSL.new.generate(TLS::IANA::NAMED_GROUPS.fetch(group))
    Extension::KeyShare::Entry.new(group:, key_exchange: key_pair.public_bytes)
  end

  def server_hello(ch, suite: 0x1301, echo: ch.legacy_session_id, extensions: nil, random: "\x01".b * 32)
    extensions ||= [Extension::KeyShare::SH.new(server_share: share), Extension::SupportedVersions::SH.new(selected_version: 0x0304)]
    Handshake::ServerHello.new(legacy_version: 0x0303, random:, legacy_session_id_echo: echo, cipher_suite: suite,
      legacy_compression_method: 0, extensions:)
  end

  def hello_retry_request(ch, group: 0x0017, suite: 0x1301, cookie: nil, extra: [])
    extensions = [Extension::SupportedVersions::SH.new(selected_version: 0x0304)]
    extensions.unshift(Extension::KeyShare::HRR.new(selected_group: group)) if group
    extensions << Extension::Cookie.new(cookie:) if cookie
    server_hello(ch, suite:, extensions: extensions + extra, random: Handshake::ServerHello::HELLO_RETRY_REQUEST_RANDOM)
  end

  def deliver(machine, message, epoch: :initial, trailing: "".b)
    machine.receive(message.encode + trailing, epoch:, now: NOW)
    failure(machine)
  end

  UNSOLICITED = Extension::Opaque.new(type: 0xff99, data: "".b)

  # :wait_sh, ServerHello rows 1, 2, 3, 7, 8 and 10.
  def test_server_hello_rows
    cases = {
      [:illegal_parameter, :cipher_suite_not_offered] => ->(ch) { server_hello(ch, suite: 0x1302) },
      [:illegal_parameter, :legacy_session_id_echo] => ->(ch) { server_hello(ch, echo: "".b) },
      [:unsupported_extension, :unsolicited_extension] => lambda do |ch|
        sh = server_hello(ch)
        sh.with(extensions: sh.extensions + [UNSOLICITED])
      end,
      [:illegal_parameter, :missing_key_share] => lambda do |ch|
        server_hello(ch, extensions: [Extension::SupportedVersions::SH.new(selected_version: 0x0304)])
      end,
      [:illegal_parameter, :key_share_group_not_offered] => lambda do |ch|
        server_hello(ch, extensions: [Extension::KeyShare::SH.new(server_share: share(0x0017)),
          Extension::SupportedVersions::SH.new(selected_version: 0x0304)])
      end,
      [:illegal_parameter, :invalid_key_share] => lambda do |ch|
        zero = Extension::KeyShare::Entry.new(group: 0x001d, key_exchange: "\x00".b * 32)
        server_hello(ch, extensions: [Extension::KeyShare::SH.new(server_share: zero), Extension::SupportedVersions::SH.new(selected_version: 0x0304)])
      end
    }
    cases.each do |expected, build|
      machine, ch = client
      assert_equal expected, deliver(machine, build.call(ch)), expected.last
    end
  end

  # Two violations at once: the earlier row decides.
  def test_server_hello_rows_in_order
    {
      [:illegal_parameter, :cipher_suite_not_offered] => ->(ch) { server_hello(ch, suite: 0x1302, echo: "".b) },
      [:illegal_parameter, :legacy_session_id_echo] => lambda do |ch|
        sh = server_hello(ch, echo: "".b)
        sh.with(extensions: sh.extensions + [UNSOLICITED])
      end,
      [:unsupported_extension, :unsolicited_extension] => lambda do |ch|
        server_hello(ch, extensions: [Extension::SupportedVersions::SH.new(selected_version: 0x0304), UNSOLICITED])
      end
    }.each do |expected, build|
      machine, ch = client
      assert_equal expected, deliver(machine, build.call(ch)), expected.last
    end
  end

  # RFC 9846 "Server Hello": a TLS 1.3 server that falls back marks its
  # random, and a client that sees the mark must abort.
  def test_downgrade_sentinel
    renegotiation_info = [Extension::Opaque.new(type: 0xff01, data: "\x00\x00".b)]
    machine, ch = client
    tls12 = server_hello(ch, extensions: renegotiation_info, random: "\x01".b * 24 + "DOWNGRD\x01".b)
    assert_equal [:illegal_parameter, :downgrade_sentinel], deliver(machine, tls12)
    machine, ch = client
    assert_equal [:protocol_version, :supported_versions], deliver(machine, server_hello(ch, extensions: renegotiation_info))
  end

  # HelloRetryRequest rows 4, 5 and 6.
  def test_hello_retry_request_rows
    machine, ch = client(groups: %i[x25519 secp256r1])
    assert_equal [:unexpected_message, :data_after_hello_retry_request], deliver(machine, hello_retry_request(ch), trailing: "\x02".b)
    [0x001d, 0x0019].each do |group|
      machine, ch = client(groups: %i[x25519 secp256r1])
      assert_equal [:illegal_parameter, :hello_retry_request_group], deliver(machine, hello_retry_request(ch, group:)), group
    end
    machine, ch = client(groups: %i[x25519 secp256r1])
    assert_equal [:illegal_parameter, :hello_retry_request_changes_nothing], deliver(machine, hello_retry_request(ch, group: nil))
    # 3 comes before 4.
    machine, ch = client(groups: %i[x25519 secp256r1])
    assert_equal [:unsupported_extension, :unsolicited_extension],
      deliver(machine, hello_retry_request(ch, extra: [UNSOLICITED]), trailing: "\x02".b)
    # 4 before 5.
    machine, ch = client(groups: %i[x25519 secp256r1])
    assert_equal [:unexpected_message, :data_after_hello_retry_request],
      deliver(machine, hello_retry_request(ch, group: 0x001d), trailing: "\x02".b)
  end

  def after_hello_retry_request
    machine, ch = client(groups: %i[x25519 secp256r1])
    machine.receive(hello_retry_request(ch).encode, epoch: :initial, now: NOW)
    [machine, parse(machine.outputs.first.bytes)]
  end

  # :wait_sh2 rows 0a, 0b and 0c, which come before the rest.
  def test_after_hello_retry_request_rows
    machine, ch2 = after_hello_retry_request
    assert_equal [:unexpected_message, :second_hello_retry_request], deliver(machine, hello_retry_request(ch2))
    machine, ch2 = after_hello_retry_request
    # The changed suite is not offered either; 0b comes before 1.
    assert_equal [:illegal_parameter, :cipher_suite_changed], deliver(machine, server_hello(ch2, suite: 0x1302))
    machine, ch2 = after_hello_retry_request
    assert_equal [:illegal_parameter, :key_share_group_changed], deliver(machine, server_hello(ch2))
    machine, ch2 = after_hello_retry_request
    p256 = server_hello(ch2, extensions: [Extension::KeyShare::SH.new(server_share: share(0x0017)),
      Extension::SupportedVersions::SH.new(selected_version: 0x0304)])
    assert_nil deliver(machine, p256)
  end

  # The server's flight with one message replaced, delivered in order.
  def with_server_flight(client_options: {}, server_config: Pair.server_config, client_identities: [])
    machine = Pair.client(config: Pair.client_config(**client_options), identities: client_identities)
    server = Pair.server(machine.outputs.first.bytes, config: server_config)
    flight = server.outputs.grep(TLS::Output::Message).map { |m| [m.epoch, parse(m.bytes)] }
    flight = yield(flight)
    flight.each do |epoch, message|
      machine.receive(message.encode, epoch:, now: NOW)
      break if machine.failed?
    end
    failure(machine)
  end

  def replace(flight, type)
    flight.map { |epoch, message| [epoch, message.msg_type == type ? yield(message) : message] }
  end

  def test_encrypted_extensions_rows
    assert_equal [:unsupported_extension, :unsolicited_extension],
      with_server_flight { |f| replace(f, 8) { |ee| ee.with(extensions: ee.extensions + [UNSOLICITED]) } }
    assert_equal [:no_application_protocol, :alpn_not_offered], with_server_flight(client_options: { alpn: ["h2"] }) { |f|
      replace(f, 8) { |ee| ee.with(extensions: [Extension::Alpn.new(protocol_name_list: ["h3"])]) }
    }
    # 1 before 4: ALPN the client did not offer at all is unsolicited.
    assert_equal [:unsupported_extension, :unsolicited_extension],
      with_server_flight { |f| replace(f, 8) { |ee| ee.with(extensions: [Extension::Alpn.new(protocol_name_list: ["h3"])]) } }
    # TCP refuses QUIC transport parameters both ways.
    assert_equal [:unsupported_extension, :forbidden_extension],
      with_server_flight { |f| replace(f, 8) { |ee| ee.with(extensions: [Extension::Opaque.new(type: 0x39, data: "".b)]) } }
  end

  def quic_flight(&)
    machine = Pair.client(config: Pair.client_config(profile: TLS::Profile::QUIC, alpn: ["h3"]),
      extensions: [Extension::Opaque.new(type: 0x39, data: "c".b)])
    server = Pair.server(machine.outputs.first.bytes, config: Pair.server_config(profile: TLS::Profile::QUIC, alpn: ["h3"]),
      extensions: [Extension::Opaque.new(type: 0x39, data: "s".b)])
    flight = server.outputs.grep(TLS::Output::Message).map { |m| [m.epoch, parse(m.bytes)] }
    replace(flight, 8, &).each { |epoch, message| machine.receive(message.encode, epoch:, now: NOW) unless machine.failed? }
    failure(machine)
  end

  # RFC 9001: ALPN must be agreed, and transport parameters are required.
  def test_quic_encrypted_extensions_rows
    assert_equal [:no_application_protocol, :alpn_not_selected],
      quic_flight { |ee| ee.with(extensions: ee.extensions.reject { |e| e.extension_type == 16 }) }
    assert_equal [:missing_extension, :required_extension],
      quic_flight { |ee| ee.with(extensions: ee.extensions.reject { |e| e.extension_type == 0x39 }) }
    # 5 before 6.
    assert_equal [:no_application_protocol, :alpn_not_selected],
      quic_flight { |ee| ee.with(extensions: ee.extensions.reject { |e| [16, 0x39].include?(e.extension_type) }) }
  end

  def test_certificate_rows
    auth = Pair.server_config(client_auth: :required)
    assert_equal [:decode_error, :certificate_request_context], with_server_flight(server_config: auth) { |f|
      replace(f, 13) { |cr| cr.with(certificate_request_context: "\x01".b) }
    }
    assert_equal [:decode_error, :certificate_request_context],
      with_server_flight { |f| replace(f, 11) { |cert| cert.with(certificate_request_context: "\x01".b) } }
    assert_equal [:decode_error, :empty_certificate],
      with_server_flight { |f| replace(f, 11) { |cert| cert.with(certificate_list: []) } }
    # 2 before 3.
    assert_equal [:decode_error, :certificate_request_context],
      with_server_flight { |f| replace(f, 11) { |cert| cert.with(certificate_request_context: "\x01".b, certificate_list: []) } }
    assert_equal [:unknown_ca, :certificate_rejected], with_server_flight(client_options: { trust_anchors: [PKI_OTHER.der] }) { |f| f }
    status_request = Extension::Opaque.new(type: 5, data: "".b)
    assert_equal [:unsupported_extension, :unsolicited_extension], with_server_flight { |f|
      replace(f, 11) { |cert| cert.with(certificate_list: cert.certificate_list.map { |e| e.with(extensions: [status_request]) }) }
    }
  end

  PKI_OTHER = NextTestPKI.ca(name: "Unrelated CA", key: NextTestPKI.key(:unrelated_ca))

  # RFC 9846 "Certificate": chains longer than the Config allows are not
  # walked.
  def test_certificate_chain_length
    assert_equal [:decode_error, :certificate_chain_too_long],
      with_server_flight(client_options: { max_certificate_chain_length: 1 }) { |f| f }
  end

  def test_certificate_verify_rows
    offered = { signature_algorithms: %i[ecdsa_secp256r1_sha256 rsa_pss_rsae_sha256] }
    # Not offered.
    assert_equal [:illegal_parameter, :signature_algorithm],
      with_server_flight(client_options: offered) { |f| replace(f, 15) { |cv| cv.with(algorithm: 0x0503) } }
    # Offered, but not for the certificate's key.
    assert_equal [:illegal_parameter, :signature_algorithm],
      with_server_flight(client_options: offered) { |f| replace(f, 15) { |cv| cv.with(algorithm: 0x0804) } }
    assert_equal [:decrypt_error, :bad_signature], with_server_flight { |f|
      replace(f, 15) { |cv| cv.with(signature: cv.signature.reverse) }
    }
    # 1 before 2.
    assert_equal [:illegal_parameter, :signature_algorithm], with_server_flight { |f|
      replace(f, 15) { |cv| cv.with(algorithm: 0x0804, signature: cv.signature.reverse) }
    }
  end

  def test_finished_rows
    assert_equal [:decrypt_error, :bad_finished], with_server_flight { |f|
      replace(f, 20) { |fin| fin.with(verify_data: fin.verify_data.reverse) }
    }
    # Of another length than the hash's, the Finished does not decode.
    assert_equal [:decode_error, :malformed_message], with_server_flight { |f|
      replace(f, 20) { |fin| fin.with(verify_data: fin.verify_data.byteslice(0, 31)) }
    }
  end

  # After a failure nothing more comes out, whatever arrives.
  def test_nothing_after_a_failure
    machine, ch = client
    deliver(machine, server_hello(ch, suite: 0x1302))
    machine.outputs
    machine.receive(server_hello(ch).encode, epoch: :initial, now: NOW)
    machine.receive("\x08\x00\x00\x02\x00\x00".b, epoch: :handshake, now: NOW)
    assert_empty machine.outputs
    assert_empty machine.each_event.to_a
  end
end
