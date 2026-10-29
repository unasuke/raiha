require "raiha/next/test_helper"
require "raiha/next/support/runtime_http3"
require "async"

# The HTTP/3 server of the runtime against its HTTP/3 client: each request
# in a fiber of its own with its pseudo-header and header fields, its body
# as it comes and its trailers, answered whole; a request left without a
# response is answered with 500.
class RaihaNextRuntimeHTTP3ServerTest < Minitest::Test
  include NextRuntimeHTTP3

  # A server of HTTP/3 on a free port with `handler` for each request, for
  # the block, which is given its port, the server and the fiber running
  # it; stopped after.
  def serving(handler, settings: HTTP3::Settings.new)
    tls = h3_server_config
    server = Runtime::HTTP3::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1",
      port: 0, settings:)
    running = Fiber.schedule { server.run(&handler) }
    sleep 0.01 until server.local_address
    yield server.local_address.fetch(1), server, running
  ensure
    server&.stop(timeout: 1)
    sleep 0.01 while running&.alive?
  end

  def client(port, &) = h3_connect(port) { |session| yield Runtime::HTTP3::Client.new(session) }

  def test_a_request_and_its_response
    seen = nil
    handler = lambda do |request|
      seen = [request.method, request.path, request.authority, request.scheme, request.protocol, request.headers]
      request.respond(200, [["content-type", "text/plain"]], "hello")
    end
    Sync do
      serving(handler) do |port|
        response = client(port) { _1.get("/greeting", headers: [["accept", "*/*"]]) }
        assert_equal [200, [["content-type", "text/plain"]], "hello"], [response.status, response.headers, response.body]
      end
    end
    assert_equal ["GET", "/greeting", "localhost", "https", nil, [["accept", "*/*"]]], seen
  end

  # A body read as it comes, a megabyte held back by flow control, and the
  # trailers after it.
  def test_a_request_body
    handler = ->(request) { request.respond(200, [], "#{request.body.read.bytesize} #{request.trailers.inspect}") }
    Sync do
      serving(handler) do |port|
        large = Random.new(5).bytes(1_000_000)
        assert_equal "1000000 []", client(port) { _1.request("POST", "/upload", body: large).body }
      end
    end
  end

  def test_requests_in_fibers_of_their_own
    handler = lambda do |request|
      sleep 0.05 if request.path == "/slow"
      request.respond(200, [], request.path)
    end
    Sync do
      serving(handler) do |port|
        client(port) do |client|
          bodies = {}
          fibers = %w[/slow /fast].map { |path| Fiber.schedule { bodies[path] = [client.get(path).body, Runtime::Driver.clock] } }
          sleep 0.01 while fibers.any?(&:alive?)
          assert_equal({ "/slow" => "/slow", "/fast" => "/fast" }, bodies.transform_values(&:first))
          assert_operator bodies.fetch("/fast").last, :<, bodies.fetch("/slow").last
        end
      end
    end
  end

  # A body written as it goes, a megabyte held back by flow control, and
  # trailer fields after it.
  def test_a_response_written_as_it_goes
    large = Random.new(6).bytes(1_000_000)
    handler = lambda do |request|
      request.respond(200, [["content-type", "application/octet-stream"]]) do |body|
        large.bytes.each_slice(100_000) { |slice| body << slice.pack("C*") }
        body.trailers = [["x-parts", "10"]]
      end
    end
    Sync do
      serving(handler) do |port|
        response = client(port) { _1.get("/stream") }
        assert_equal [200, large, [["x-parts", "10"]]], [response.status, response.body, response.trailers]
      end
    end
  end

  # The priority given to a response overrides what the request asked,
  # only as far as it gives.
  def test_the_priority_of_a_response
    priorities = []
    handler = lambda do |request|
      serving = request.instance_variable_get(:@server)
      http3 = serving.instance_variable_get(:@http3)
      request.priority = { urgency: 1 }
      priorities << http3.send(:priority_of, request.stream_id)
      request.respond(200, [], "prioritized")
    end
    Sync do
      serving(handler) do |port|
        assert_equal "prioritized", client(port) { _1.request("GET", "/", urgency: 5, incremental: true).body }
      end
    end
    assert_equal [Raiha::Next::HTTP3::Priority.new(urgency: 1, incremental: true)], priorities
  end

  # A block that raises before its response has it answered with 500, and
  # in the middle of it has the request reset with H3_INTERNAL_ERROR; the
  # connection goes on.
  def test_a_block_that_raises
    level = Console.logger.level
    Console.logger.off!
    handler = lambda do |request|
      raise "before" if request.path == "/before"
      return request.respond(200, [], "fine") if request.path == "/fine"
      request.respond(200) do |body|
        body << "partial"
        raise "during"
      end
    end
    Sync do
      serving(handler) do |port|
        client(port) do |client|
          assert_equal 500, client.get("/before").status
          error = assert_raises(Runtime::HTTP3::StreamReset) { client.get("/during") }
          assert_equal HTTP3::ErrorCode::INTERNAL_ERROR, error.error_code
          assert_equal "fine", client.get("/fine").body
        end
      end
    end
  ensure
    Console.logger.level = level
  end

  # Extended CONNECT is offered only when the settings offer it, and one the
  # block does not answer is a 501.
  def test_an_extended_connect_not_taken
    Sync do
      serving(->(_request) {}) do |port|
        refute(h3_connect(port) { |session| ConnectRequest.new(session, protocol: "websocket").offered? })
      end
      serving(->(_request) {}, settings: HTTP3::Settings.new(enable_connect_protocol: true)) do |port|
        status = h3_connect(port) do |session|
          ConnectRequest.new(session, protocol: "websocket").status
        end
        assert_equal "501", status
      end
    end
  end

  # A client's HTTP/3 that sends one Extended CONNECT (RFC 9220) and waits
  # for the status of its response.
  class ConnectRequest
    HTTP3 = Raiha::Next::HTTP3

    def initialize(session, protocol:)
      @session = session
      @http3 = HTTP3::Connection.client
      @binding = Raiha::Next::HTTP3Binding.new(session.connection, @http3)
      @protocol = protocol
      @status = nil
      session.attach(self)
    end

    # Whether the server offers Extended CONNECT, once its SETTINGS have come.
    def offered?
      @session.wait_for { @http3.peer_settings }.enable_connect_protocol
    end

    def status
      stream_id = nil
      @session.wait_for { @http3.peer_settings&.enable_connect_protocol || nil }
      stream_id = @session.open_stream_id
      @http3.send_request(stream_id, [[":method", "CONNECT"], [":protocol", @protocol], [":scheme", "https"], [":authority", "localhost"],
        [":path", "/chat"]])
      @binding.flush(now: Raiha::Next::Runtime::Driver.clock)
      @session.changed
      @session.wait_for { @status }
    end

    def take(event, now) = @binding.receive(event, now:)

    def expire = nil

    def turn(now)
      @binding.flush(now:)
      @http3.each_event { |event| @status = event.headers.to_h[":status"] if event.is_a?(HTTP3::Event::Headers) }
      @binding.flush(now:)
    end
  end

  # A server asked to stop sends GOAWAY twice, lets the request it took
  # finish, and closes with H3_NO_ERROR once its response is acknowledged,
  # well before the timeout.
  def test_stop
    handler = lambda do |request|
      sleep 0.3
      request.respond(200, [], "finished")
    end
    Sync do
      serving(handler) do |port, server, running|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          started = Runtime::Driver.clock
          Fiber.schedule do
            sleep 0.05
            server.stop(timeout: 5)
          end
          assert_equal "finished", client.get("/slow").body
          sleep 0.01 until session.closed?
          assert_operator Runtime::Driver.clock - started, :<, 2
          assert_equal [HTTP3::ErrorCode::NO_ERROR, true], session.connection.close_reason.then { [_1.code, _1.application] }
          assert_equal 4, client.instance_variable_get(:@http3).instance_variable_get(:@peer_goaway)
        end
        sleep 0.01 while running.alive?
      end
    end
  end

  # A request over before its fiber is known does not hold a stop back.
  def test_stop_after_a_request_over_at_once
    Sync do
      serving(->(request) { request.respond(200, [], "at once") }) do |port, server, running|
        h3_connect(port) do |session|
          assert_equal "at once", Runtime::HTTP3::Client.new(session).get("/").body
          started = Runtime::Driver.clock
          server.stop(timeout: 5)
          sleep 0.01 until session.closed?
          assert_operator Runtime::Driver.clock - started, :<, 2
        end
        sleep 0.01 while running.alive?
      end
    end
  end

  # A request still running when the server is out of time is cancelled, and
  # its fiber interrupted where it waits.
  def test_stop_out_of_time
    interrupted = nil
    handler = lambda do |request|
      sleep 10
      request.respond(200)
    rescue Runtime::HTTP3::StreamReset => error
      interrupted = error.error_code
      raise
    end
    Sync do
      serving(handler) do |port, server, running|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          Fiber.schedule do
            sleep 0.05
            server.stop(timeout: 0.3)
          end
          error = assert_raises(Runtime::HTTP3::StreamReset, Raiha::Next::QUIC::ClosedError) { client.get("/forever") }
          assert_equal HTTP3::ErrorCode::REQUEST_CANCELLED, error.error_code if error.is_a?(Runtime::HTTP3::StreamReset)
        end
        sleep 0.01 while running.alive?
      end
    end
    assert_equal HTTP3::ErrorCode::REQUEST_CANCELLED, interrupted
  end

  # Only a final status makes a response; an interim one is the block's
  # mistake, answered with 500.
  def test_an_interim_status
    level = Console.logger.level
    Console.logger.off!
    Sync do
      serving(->(request) { request.respond(103, [["link", "</style.css>"]]) }) do |port|
        assert_equal 500, client(port) { _1.get("/").status }
      end
    end
  ensure
    Console.logger.level = level
  end

  def test_no_response_is_a_500
    Sync do
      serving(->(_request) {}) do |port|
        assert_equal [500, ""], client(port) { _1.get("/").then { |response| [response.status, response.body] } }
      end
    end
  end
end
