require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# The output sequences of the state machine design's table, for each role,
# Profile and handshake without PSK. Without 0-RTT there is no
# EndOfEarlyData, so TCP and QUIC come out the same. RFC 8448 confirms the
# TCP sequences byte for byte (test/rfc8448_handshake_test.rb).
class RaihaNextTLSOutputGoldenTest < Minitest::Test
  TLS = Raiha::Next::TLS
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
end
