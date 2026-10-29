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
  # the block, which is given its port; stopped after.
  def serving(handler)
    tls = h3_server_config
    server = Runtime::HTTP3::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1",
      port: 0)
    running = Fiber.schedule { server.run(&handler) }
    sleep 0.01 until server.local_address
    yield server.local_address.fetch(1)
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

  def test_no_response_is_a_500
    Sync do
      serving(->(_request) {}) do |port|
        assert_equal [500, ""], client(port) { _1.get("/").then { |response| [response.status, response.body] } }
      end
    end
  end
end
