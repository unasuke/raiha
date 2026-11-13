require "test_helper"
require "support/tls_pair"

# The output sequences of the state machine design's table, for each role,
# Profile and handshake. Without 0-RTT there is no EndOfEarlyData, so TCP
# and QUIC come out the same. RFC 8448 confirms the TCP sequences byte for
# byte (test/rfc8448_handshake_test.rb), for the client of section 4 too.
class RaihaNextTLSOutputGoldenTest < Minitest::Test
  TLS = Raiha::TLS
  Pair = NextTLSPair

  CLIENT_HELLO = [:message, :initial, 1].freeze
  HANDSHAKE_KEYS = [[:secret, :handshake, :read], [:secret, :handshake, :write]].freeze
  APPLICATION_KEYS = [[:secret, :application, :read], [:secret, :application, :write]].freeze

  def server_first_flight(*middle)
    [*HANDSHAKE_KEYS, [:secret, :application, :write], [:message, :initial, 2], [:message, :handshake, 8], *middle,
      [:message, :handshake, 11], [:message, :handshake, 15], [:message, :handshake, 20]]
  end

  CLIENT = {
    full: [CLIENT_HELLO, *HANDSHAKE_KEYS, *APPLICATION_KEYS, [:message, :handshake, 20]],
    hello_retry_request: [CLIENT_HELLO, CLIENT_HELLO, *HANDSHAKE_KEYS, *APPLICATION_KEYS, [:message, :handshake, 20]],
    client_authentication: [CLIENT_HELLO, *HANDSHAKE_KEYS, *APPLICATION_KEYS, [:message, :handshake, 11],
      [:message, :handshake, 15], [:message, :handshake, 20]]
  }.freeze

  def run_scenario(scenario, profile)
    quic = profile == TLS::Profile::QUIC
    tp = quic ? [TLS::Extension::Opaque.new(type: 0x39, data: "tp".b)] : []
    options = quic ? { profile:, alpn: ["h3"] } : { profile: }
    server_options = { **options }
    server_options[:groups] = %i[secp256r1] if scenario == :hello_retry_request
    server_options[:client_auth] = :required if scenario == :client_authentication
    client = Pair.client(config: Pair.client_config(**options), extensions: tp, identities: [Pair.client_identity])
    Pair.run(client, { config: Pair.server_config(**server_options), extensions: tp })
  end

  # The server's whole run: its first flight, after a HelloRetryRequest
  # when there is one, then the client's application key.
  def expected_server(scenario)
    case scenario
    when :full then [*server_first_flight, [:secret, :application, :read]]
    when :hello_retry_request then [[:message, :initial, 2], *server_first_flight, [:secret, :application, :read]]
    else [*server_first_flight([:message, :handshake, 13]), [:secret, :application, :read]]
    end
  end

  [TLS::Profile::TCP, TLS::Profile::QUIC].each do |profile|
    name = profile == TLS::Profile::TCP ? "tcp" : "quic"
    CLIENT.each_key do |scenario|
      define_method(:"test_#{name}_#{scenario}") do
        pair = run_scenario(scenario, profile)
        assert pair.client.complete?
        assert pair.server.complete?
        assert_equal CLIENT.fetch(scenario), Pair.shape(pair.client_outputs), "client"
        assert_equal expected_server(scenario), Pair.shape(pair.server_outputs), "server"
      end
    end
  end

  SEED = "\x15".b * 32
  TICKETS = [[:message, :application, 4]] * 2

  # A session of a server that takes 0-RTT, and the client and server
  # options that resume it under `profile`.
  def resumption(profile)
    quic = profile == TLS::Profile::QUIC
    tp = quic ? [TLS::Extension::Opaque.new(type: 0x39, data: "tp".b)] : []
    client_config = Pair.client_config(**(quic ? { profile:, alpn: ["h3"] } : { profile: }))
    server_config = Pair.server_config(ticket_key: SEED, max_early_data_size: 1024, **(quic ? { profile:, alpn: ["h3"] } : { profile: }))
    server = { config: server_config, extensions: tp, early_data_context: "context".b }
    pair = Pair.run(Pair.client(config: client_config, extensions: tp), server)
    Pair.deliver(pair.server_outputs.select { |output| output.is_a?(TLS::Output::Message) && output.epoch == :application }, pair.client)
    session = pair.client.each_event.grep(TLS::Event::NewSessionTicket).first.session
    [session, { config: client_config, extensions: tp }, server]
  end

  RESUMED_SERVER = [*HANDSHAKE_KEYS, [:secret, :application, :write], [:message, :initial, 2], [:message, :handshake, 8],
    [:message, :handshake, 20], [:secret, :application, :read], *TICKETS].freeze

  [TLS::Profile::TCP, TLS::Profile::QUIC].each do |profile|
    name = profile == TLS::Profile::TCP ? "tcp" : "quic"

    define_method(:"test_#{name}_psk") do
      session, client, server = resumption(profile)
      pair = Pair.run(Pair.client(session:, **client), server)
      assert_equal [CLIENT_HELLO, *HANDSHAKE_KEYS, *APPLICATION_KEYS, [:message, :handshake, 20]], Pair.shape(pair.client_outputs)
      assert_equal RESUMED_SERVER, Pair.shape(pair.server_outputs)
    end

    # 0-RTT's keys come first; EndOfEarlyData only where there is a record
    # layer.
    define_method(:"test_#{name}_psk_0rtt_accepted") do
      session, client, server = resumption(profile)
      pair = Pair.run(Pair.client(session:, early_data: true, **client), server)
      end_of_early_data = profile.send_end_of_early_data ? [[:message, :early_data, 5]] : []
      assert_equal [[:secret, :early_data, :write], CLIENT_HELLO, *HANDSHAKE_KEYS, *APPLICATION_KEYS, *end_of_early_data,
        [:message, :handshake, 20]], Pair.shape(pair.client_outputs)
      assert_equal [[:secret, :early_data, :read], *RESUMED_SERVER], Pair.shape(pair.server_outputs)
    end

    define_method(:"test_#{name}_psk_0rtt_rejected") do
      session, client, server = resumption(profile)
      pair = Pair.run(Pair.client(session:, early_data: true, **client), server.merge(early_data_context: "other".b))
      assert_equal [[:secret, :early_data, :write], CLIENT_HELLO, *HANDSHAKE_KEYS, *APPLICATION_KEYS, [:message, :handshake, 20]],
        Pair.shape(pair.client_outputs)
      assert_equal RESUMED_SERVER, Pair.shape(pair.server_outputs)
    end
  end
end
