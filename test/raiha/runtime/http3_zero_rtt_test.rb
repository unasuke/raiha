require "test_helper"
require "support/runtime_http3"
require "async"

# Resumption and 0-RTT of the runtime's HTTP/3: a server's 0-RTT bound to
# its SETTINGS.
class RaihaRuntimeHTTP3ZeroRTTTest < Minitest::Test
  include RuntimeHTTP3

  SEED = "\x22".b * 32

  # One TLS Config for every server, so that a ticket of one resumes
  # another.
  def tls = @tls ||= TLSPair.server_config(profile: TLS::Profile::QUIC, alpn: H3, registry: REGISTRY, ticket_key: SEED, max_early_data_size: 16_384)

  # A server of HTTP/3 on a free port answering each request with
  # `handler`, for the block, which is given its port; stopped after. It
  # takes `hold` seconds over each ClientHello, so that on the loopback
  # interface a client's 0-RTT goes before the server's flight comes, and
  # with it the keys of 1-RTT.
  def serving(handler = ->(request) { request.respond(200, [], "ok") }, settings: HTTP3::Settings.new,
    anti_replay: TLS::AntiReplay::Memory.new(now: Time.now, warmup: false), hold: 0)
    server = Runtime::HTTP3::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1",
      port: 0, settings:, anti_replay:)
    server.instance_variable_get(:@server).define_singleton_method(:route) do |route, now|
      sleep hold if route.is_a?(QUIC::Route::ClientHello)
      super(route, now)
    end
    running = Fiber.schedule { server.run(&handler) }
    sleep 0.01 until server.local_address
    yield server.local_address.fetch(1)
  ensure
    server&.stop(timeout: 1)
    sleep 0.01 while running&.alive?
  end

  # A ticket the server on `port` gives, as a QUIC::Session.
  def quic_ticket(port)
    h3_connect(port) do |session|
      session.wait_for(deadline: Runtime::Driver.clock + 2) { session.tickets.first }
      session.tickets.last
    end
  end

  # The tickets of the client of HTTP/3 come with the server's SETTINGS.
  def test_tickets_with_the_servers_settings
    Sync do
      settings = HTTP3::Settings.new(max_field_section_size: 1000)
      tickets = serving(settings:) do |port|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          assert_equal "ok", client.get("/").body
          session.wait_for(deadline: Runtime::Driver.clock + 2) { client.tickets.first }
          client.tickets
        end
      end
      refute_empty tickets
      assert_equal [settings], tickets.map(&:settings).uniq
      assert_equal [QUIC::Session], tickets.map { _1.quic.class }.uniq
    end
  end

  # A server's SETTINGS are part of what its 0-RTT is taken with: the
  # ticket of a server of other SETTINGS resumes, but its 0-RTT is
  # rejected (RFC 9114 "Initialization").
  def test_settings_bind_0rtt
    Sync do
      ticket = serving { |port| quic_ticket(port) }
      states = [HTTP3::Settings.new, HTTP3::Settings.new(max_field_section_size: 1000)].map do |settings|
        serving(settings:) do |port|
          h3_connect(port, session: ticket, early_data: true) do |session|
            session.wait_handshake
            [session.handshake&.resumed, session.connection.zero_rtt_state]
          end
        end
      end
      assert_equal [[true, :accepted], [true, :rejected]], states
    end
  end

  # A ticket of the client of HTTP/3 the server on `port` gives, once it has
  # one.
  def h3_ticket(port)
    h3_connect(port) do |session|
      client = Runtime::HTTP3::Client.new(session)
      session.wait_for(deadline: Runtime::Driver.clock + 2) { client.tickets.first }
      client.tickets.last
    end
  end

  # With a ticket of the client of HTTP/3, a request goes before the
  # handshake completes, to the authority of the server's name.
  def test_a_request_in_0rtt
    Sync do
      authorities = []
      handler = lambda do |request|
        authorities << request.authority
        request.respond(200, [], "ok")
      end
      answer = serving(handler, hold: 0.05) do |port|
        ticket = h3_ticket(port)
        h3_connect(port, session: ticket, early_data: true) do |session|
          client = Runtime::HTTP3::Client.new(session)
          refute session.connection.handshake_complete?
          [client.get("/").body, session.connection.zero_rtt_state]
        end
      end
      assert_equal ["ok", :accepted], answer
      assert_equal ["localhost"], authorities
    end
  end

  # A request that came in 0-RTT is early data; one after the handshake on
  # the same connection is not, and one a proxy marked with Early-Data is,
  # whatever the value.
  def test_early_data
    Sync do
      seen = {}
      handler = lambda do |request|
        seen[request.path] = request.early_data?
        request.respond(200, [], "ok")
      end
      serving(handler, hold: 0.05) do |port|
        ticket = h3_ticket(port)
        h3_connect(port, session: ticket, early_data: true) do |session|
          client = Runtime::HTTP3::Client.new(session)
          client.get("/early")
          client.get("/late")
          client.get("/marked", headers: [["early-data", "0"]])
        end
      end
      assert_equal({ "/early" => true, "/late" => false, "/marked" => true }, seen)
    end
  end

  # A server that rejects 0-RTT, its record warming up: the request that
  # went in it raises QUIC::Error::ZeroRttRejected, and one after goes in
  # 1-RTT on the stream of the same ID, HTTP/3 started over.
  def test_a_rejected_0rtt
    Sync do
      seen = []
      handler = lambda do |request|
        seen << request.path
        request.respond(200, [], "ok")
      end
      result = serving(handler, hold: 0.05, anti_replay: TLS::AntiReplay::Memory.new(now: Time.now)) do |port|
        ticket = h3_ticket(port)
        h3_connect(port, session: ticket, early_data: true) do |session|
          client = Runtime::HTTP3::Client.new(session)
          assert_raises(QUIC::Error::ZeroRttRejected) { client.get("/early") }
          [client.get("/again").body, session.connection.zero_rtt_state]
        end
      end
      assert_equal ["ok", :rejected], result
      assert_equal ["/again"], seen
    end
  end

  # What a Request asks of the server it came to.
  class Serving
    attr_writer :early

    def stream_early_data?(_stream_id) = @early
  end

  # A request whose header section came in 1-RTT, then a part of it in a
  # 0-RTT packet that came late: early data from then on.
  def test_early_data_that_comes_late
    serving = Serving.new
    serving.early = false
    request = Runtime::HTTP3::Request.new(serving, 0, Runtime::HTTP3::Exchange.new, [[":method", "GET"], [":path", "/"]])
    refute request.early_data?
    serving.early = true
    assert request.early_data?
  end
end
