require "raiha/next/test_helper"
require "raiha/next/support/runtime_http3"
require "async"

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
