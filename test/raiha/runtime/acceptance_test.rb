require "test_helper"
require "support/runtime_http3"
require "async"

# The third acceptance test of the API of the next release of raiha: an
# HTTP/3 GET under a Fiber scheduler, written as the design writes it, to
# a server of the runtime on the loopback interface.
class RaihaNextRuntimeAcceptanceTest < Minitest::Test
  include NextRuntimeHTTP3

  def test_an_http3_get_under_a_fiber_scheduler
    server_tls = h3_server_config
    server = Raiha::Runtime::HTTP3::Server.new(config: QUIC::Config.new, tls_config: server_tls,
      keyring: server_keyring(config: server_tls), host: "::", port: 0)
    config = QUIC::Config.new
    # A Keyring is for the Config it was built with.
    tls_config = NextTLSPair.client_config(profile: TLS::Profile::QUIC, registry: REGISTRY).with(alpn: ["h3"])
    keyring = TLS::Keyring.client(config: tls_config)
    body = nil
    Async do
      running = Fiber.schedule { server.run { |request| request.respond(200, [["content-type", "text/plain"]], "hello from #{request.path}") } }
      sleep 0.01 until server.local_address
      port = server.local_address.fetch(1)

      Raiha::Runtime::Client.connect("localhost", port, config:, tls_config:, keyring:) do |session|
        response = Raiha::Runtime::HTTP3::Client.new(session).get("/")
        body = response.body
      end
    ensure
      server.stop(timeout: 1)
      sleep 0.01 while running&.alive?
    end.wait
    assert_equal "hello from /", body
  end
end
