require "test_helper"
require "support/threaded_http3"
require "stringio"

# The HTTP/3 server of the runtime on threads against its HTTP/3 client on
# threads: each request in a thread of its own with its pseudo-header and
# header fields, its body as it comes and its trailers, answered whole; no
# more request threads than it is given, a request left without a response
# answered with 500, and one out of time cancelled without interrupting
# its thread.
class RaihaRuntimeThreadedHTTP3ServerTest < Minitest::Test
  include ThreadedHTTP3

  # A server of HTTP/3 on threads on a free port with `handler` for each
  # request, for the block, which is given its port, the server and the
  # thread running it; stopped after.
  def serving(handler, settings: HTTP3::Settings.new, **options)
    tls = h3_server_config
    server = Threaded::HTTP3::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1",
      port: 0, settings:, **options)
    running = Thread.new { server.run(&handler) }
    sleep 0.01 until server.local_address
    yield server.local_address.fetch(1), server, running
  ensure
    server&.stop(timeout: 1)
    running&.join(10)
  end

  def client(port, &) = h3_connect(port) { |session| yield Threaded::HTTP3::Client.new(session) }

  # Runs the block with the threads it starts reporting no exception.
  def quietly
    report = Thread.report_on_exception
    Thread.report_on_exception = false
    yield
  ensure
    Thread.report_on_exception = report
  end

  def test_a_request_and_its_response
    seen = nil
    handler = lambda do |request|
      seen = [request.method, request.path, request.authority, request.scheme, request.protocol, request.headers, Thread.current.name,
        Fiber.scheduler]
      request.respond(200, [["content-type", "text/plain"]], "hello")
    end
    serving(handler) do |port|
      response = client(port) { _1.get("/greeting", headers: [["accept", "*/*"]]) }
      assert_equal [200, [["content-type", "text/plain"]], "hello"], [response.status, response.headers, response.body]
    end
    assert_equal ["GET", "/greeting", "localhost", "https", nil, [["accept", "*/*"]], "raiha-request", nil], seen
  end

  # A body read as it comes, a megabyte held back by flow control, and the
  # trailers after it.
  def test_a_request_body
    handler = ->(request) { request.respond(200, [], "#{request.body.read.bytesize} #{request.trailers.inspect}") }
    serving(handler) do |port|
      large = Random.new(5).bytes(1_000_000)
      assert_equal "1000000 []", client(port) { _1.request("POST", "/upload", body: large).body }
    end
  end

  # A request answered without its body: the client is told to send no
  # more of it, and has the response all the same.
  def test_a_request_body_not_read
    body = StringIO.new(Random.new(5).bytes(4_000_000))
    serving(->(request) { request.respond(200, [], "no thanks") }) do |port|
      assert_equal "no thanks", client(port) { _1.request("POST", "/upload", body:).body }
    end
    assert_operator body.pos, :<, 4_000_000
  end

  def test_requests_in_threads_of_their_own
    handler = lambda do |request|
      sleep 0.05 if request.path == "/slow"
      request.respond(200, [], request.path)
    end
    serving(handler) do |port|
      client(port) do |client|
        bodies = %w[/slow /fast].to_h { |path| [path, Thread.new { [client.get(path).body, Threaded::Driver.clock] }] }.transform_values(&:value)
        assert_equal({ "/slow" => "/slow", "/fast" => "/fast" }, bodies.transform_values(&:first))
        assert_operator bodies.fetch("/fast").last, :<, bodies.fetch("/slow").last
      end
    end
  end

  # The threads of the requests are `max_threads` at most; the next request
  # waits for a place.
  def test_no_more_request_threads_than_max_threads
    most = 0
    now = 0
    lock = Mutex.new
    handler = lambda do |request|
      lock.synchronize { most = [most, now += 1].max }
      sleep 0.02
      lock.synchronize { now -= 1 }
      request.respond(200, [], request.path)
    end
    serving(handler, max_threads: 2) do |port|
      client(port) do |client|
        paths = Array.new(8) { "/#{_1}" }
        assert_equal paths, paths.map { |path| Thread.new { client.get(path).body } }.map(&:value)
      end
    end
    assert_equal 2, most
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
    serving(handler) do |port|
      response = client(port) { _1.get("/stream") }
      assert_equal [200, large, [["x-parts", "10"]]], [response.status, response.body, response.trailers]
    end
  end

  # A body closed before the block is over: the response is whole, and
  # nothing more is written to it.
  def test_a_response_closed_before_its_block_is_over
    release = Thread::Queue.new
    after = nil
    handler = lambda do |request|
      request.respond(200) do |body|
        body << "whole"
        body.trailers = [["x-done", "1"]]
        body.close
        release.pop
        after = [body.closed?, assert_raises(Runtime::Error::Usage) { body << "more" }, assert_raises(Runtime::Error::Usage) { body.trailers = [] }]
      end
    end
    serving(handler) do |port|
      response = client(port) { _1.get("/") }
      assert_equal ["whole", [["x-done", "1"]]], [response.body, response.trailers]
    ensure
      release << true
    end
    assert after.first
  end

  def test_the_priority_of_a_response
    priorities = []
    handler = lambda do |request|
      http3 = request.instance_variable_get(:@server).instance_variable_get(:@http3)
      request.priority = { urgency: 1 }
      priorities << http3.send(:priority_of, request.stream_id)
      request.respond(200, [], "prioritized")
    end
    serving(handler) do |port|
      assert_equal "prioritized", client(port) { _1.request("GET", "/", urgency: 5, incremental: true).body }
    end
    assert_equal [Raiha::HTTP3::Priority.new(urgency: 1, incremental: true)], priorities
  end

  # A block that raises before its response has it answered with 500, and
  # in the middle of it has the request reset with H3_INTERNAL_ERROR; the
  # connection goes on.
  def test_a_block_that_raises
    handler = lambda do |request|
      raise "before" if request.path == "/before"
      return request.respond(200, [], "fine") if request.path == "/fine"
      request.respond(200) do |body|
        body << "partial"
        raise "during"
      end
    end
    quietly do
      serving(handler) do |port|
        client(port) do |client|
          assert_equal 500, client.get("/before").status
          error = assert_raises(Runtime::HTTP3::StreamReset) { client.get("/during") }
          assert_equal HTTP3::ErrorCode::INTERNAL_ERROR, error.error_code
          assert_equal "fine", client.get("/fine").body
        end
      end
    end
  end

  # A block that raises once its response is whole leaves it as it is.
  def test_a_block_that_raises_after_its_response
    handler = lambda do |request|
      request.respond(200, [], "whole") if request.path == "/whole"
      request.respond(200) { |body| (body << "closed").close } if request.path == "/closed"
      raise "after"
    end
    quietly do
      serving(handler) do |port|
        client(port) do |client|
          assert_equal "whole", client.request("POST", "/whole", body: "x" * 100_000).body
          assert_equal "closed", client.request("POST", "/closed", body: "x" * 100_000).body
        end
      end
    end
  end

  # Extended CONNECT is offered only when the settings offer it, and one the
  # block does not answer is a 501.
  def test_an_extended_connect_not_taken
    serving(->(_request) {}) do |port|
      refute(h3_connect(port) { |session| ConnectRequest.new(session, protocol: "websocket").offered? })
    end
    serving(->(_request) {}, settings: HTTP3::Settings.new(enable_connect_protocol: true)) do |port|
      assert_equal "501", h3_connect(port) { |session| ConnectRequest.new(session, protocol: "websocket").status }
    end
  end

  # A client's HTTP/3 that sends one Extended CONNECT (RFC 9220) and waits
  # for the status of its response, calling HTTP/3 under the core lock.
  class ConnectRequest
    HTTP3 = Raiha::HTTP3

    def initialize(session, protocol:)
      @session = session
      @http3 = HTTP3::Connection.client
      @binding = Raiha::HTTP3Binding.new(session.core, @http3)
      @protocol = protocol
      @status = nil
      session.attach(self)
    end

    # Whether the server offers Extended CONNECT, once its SETTINGS have come.
    def offered?
      @session.wait_for { @http3.peer_settings }.enable_connect_protocol
    end

    def status
      @session.wait_for { @http3.peer_settings&.enable_connect_protocol || nil }
      @session.synchronize do
        stream_id = @session.open_stream_id
        @http3.send_request(stream_id, [[":method", "CONNECT"], [":protocol", @protocol], [":scheme", "https"], [":authority", "localhost"],
          [":path", "/chat"]])
        @binding.flush(now: Raiha::Runtime::Threaded::Driver.clock)
        @session.changed
      end
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
    serving(handler) do |port, server, running|
      h3_connect(port) do |session|
        client = Threaded::HTTP3::Client.new(session)
        started = Threaded::Driver.clock
        Thread.new do
          sleep 0.05
          server.stop(timeout: 5)
        end
        assert_equal "finished", client.get("/slow").body
        assert eventually { session.closed? }
        assert_operator Threaded::Driver.clock - started, :<, 2
        assert_equal [HTTP3::ErrorCode::NO_ERROR, true], session.connection.close_reason.then { [_1.code, _1.application] }
        assert_equal 4, client.instance_variable_get(:@http3).instance_variable_get(:@peer_goaway)
      end
      assert running.join(5)
    end
  end

  # A request over before its thread is known does not hold a stop back.
  def test_stop_after_a_request_over_at_once
    serving(->(request) { request.respond(200, [], "at once") }) do |port, server, running|
      h3_connect(port) do |session|
        assert_equal "at once", Threaded::HTTP3::Client.new(session).get("/").body
        started = Threaded::Driver.clock
        server.stop(timeout: 5)
        assert eventually { session.closed? }
        assert_operator Threaded::Driver.clock - started, :<, 2
      end
      assert running.join(5)
    end
  end

  # A request still running when the server is out of time is cancelled; its
  # thread, not interrupted, hears of it when it next writes, and `run` does
  # not wait for it.
  def test_stop_out_of_time
    cancelled = Queue.new
    handler = lambda do |request|
      sleep 1
      request.respond(200)
    rescue Runtime::HTTP3::StreamReset => error
      cancelled << error.error_code
      raise
    end
    serving(handler) do |port, server, running|
      h3_connect(port) do |session|
        client = Threaded::HTTP3::Client.new(session)
        Thread.new do
          sleep 0.05
          server.stop(timeout: 0.3)
        end
        error = assert_raises(Runtime::HTTP3::StreamReset, Raiha::QUIC::ClosedError) { client.get("/forever") }
        assert_equal HTTP3::ErrorCode::REQUEST_CANCELLED, error.error_code if error.is_a?(Runtime::HTTP3::StreamReset)
      end
      assert running.join(0.9)
    end
    assert_equal HTTP3::ErrorCode::REQUEST_CANCELLED, cancelled.pop
  end

  # Only a final status makes a response; an interim one is the block's
  # mistake, answered with 500.
  def test_an_interim_status
    quietly do
      serving(->(request) { request.respond(103, [["link", "</style.css>"]]) }) do |port|
        assert_equal 500, client(port) { _1.get("/").status }
      end
    end
  end

  def test_no_response_is_a_500
    serving(->(_request) {}) do |port|
      assert_equal [500, ""], client(port) { _1.get("/").then { |response| [response.status, response.body] } }
    end
  end
end
