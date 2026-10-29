require "raiha/next/test_helper"
require "raiha/next/support/runtime_http3"
require "async"
require "stringio"

# The HTTP/3 client of the runtime against a server's HTTP/3 on a Session
# of the runtime: a GET read whole, an informational response passed over,
# trailer fields, a cancelled request raised where it waits, and requests
# in fibers of their own over one connection.
class RaihaNextRuntimeHTTP3ClientTest < Minitest::Test
  include NextRuntimeHTTP3

  BODIES = {
    "/hello" => "hello world".b, "/early" => "after a hint".b, "/trailers" => "checked".b,
    "/large" => Random.new(3).bytes(300_000)
  }.freeze

  def test_a_get_read_whole
    Sync do
      answering(BODIES) do |port|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          response = client.get("/hello")
          assert_equal [200, [["content-length", "11"]], "hello world", []],
            [response.status, response.headers, response.body, response.trailers]
          assert_equal BODIES.fetch("/large"), client.get("/large").body
          assert_equal [404, ""], client.get("/missing").then { [_1.status, _1.body] }
        end
      end
    end
  end

  def test_an_informational_response_and_trailers
    Sync do
      answering(BODIES) do |port|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          assert_equal [200, "after a hint"], client.get("/early").then { [_1.status, _1.body] }
          assert_equal [["x-checksum", "abc"]], client.get("/trailers").trailers
        end
      end
    end
  end

  def test_a_request_the_server_cancels
    Sync do
      answering(BODIES) do |port|
        h3_connect(port) do |session|
          error = assert_raises(Runtime::HTTP3::StreamReset) { Runtime::HTTP3::Client.new(session).get("/reset") }
          assert_equal HTTP3::ErrorCode::REQUEST_CANCELLED, error.error_code
        end
      end
    end
  end

  # A request's body, a String or what reads as an IO does, goes as the
  # server takes it, a megabyte held back by flow control both ways.
  def test_a_request_with_a_body
    Sync do
      answering(BODIES) do |port|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          assert_equal "posted", client.request("POST", "/echo", body: "posted").body
          large = Random.new(4).bytes(1_000_000)
          assert_equal large, client.request("PUT", "/echo", body: StringIO.new(large)).body
        end
      end
    end
  end

  # A block takes the response as it comes, its trailers after its body.
  def test_a_response_as_it_comes
    Sync do
      answering(BODIES) do |port|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          chunks = client.request("GET", "/large") do |response|
            assert_equal 200, response.status
            [].tap { |all| response.body.each { all << _1 } }
          end
          assert_operator chunks.size, :>, 1
          assert_equal BODIES.fetch("/large"), chunks.join
          trailers = client.request("GET", "/trailers") { |response| [response.body.read, response.trailers] }
          assert_equal ["checked", [["x-checksum", "abc"]]], trailers
        end
      end
    end
  end

  # A response cancelled, or left unread by its block, stops; the
  # connection goes on.
  def test_a_response_cancelled
    Sync do
      answering(BODIES) do |port|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          client.request("GET", "/large") do |response|
            response.body.each { break }
            response.cancel
            assert_equal "", response.body.read
          end
          client.request("GET", "/large") { |response| response.status }
          assert_equal "hello world", client.get("/hello").body
          assert_empty client.instance_variable_get(:@exchanges)
        end
      end
    end
  end

  # The priority of a request goes as its priority field (RFC 9218).
  def test_a_priority
    Sync do
      answering(BODIES) do |port|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          assert_equal "u=1, i", client.request("GET", "/priority", urgency: 1, incremental: true).body
          assert_equal "none", client.get("/priority").body
          assert_raises(ArgumentError) { client.request("GET", "/priority", urgency: 8) }
        end
      end
    end
  end

  def test_requests_in_fibers_of_their_own
    Sync do
      answering(BODIES) do |port|
        h3_connect(port) do |session|
          client = Runtime::HTTP3::Client.new(session)
          bodies = {}
          fibers = %w[/hello /large /early].map { |path| Fiber.schedule { bodies[path] = client.get(path).body } }
          sleep 0.01 while fibers.any?(&:alive?)
          assert_equal BODIES.slice("/hello", "/large", "/early"), bodies
        end
      end
    end
  end
end
