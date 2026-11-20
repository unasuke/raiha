require "test_helper"
require "support/threaded_http3"
require "monitor"
require "stringio"

# The HTTP/3 client of the runtime on threads against a server's HTTP/3 on
# a Threaded::Session: a GET read whole, an informational response passed
# over, trailer fields, a cancelled request raised where it waits, requests
# from several threads at once over one connection, and no Session of the
# runtime of fibers taken.
class RaihaRuntimeThreadedHTTP3ClientTest < Minitest::Test
  include ThreadedHTTP3

  BODIES = {
    "/hello" => "hello world".b, "/last" => "last words".b, "/early" => "after a hint".b, "/trailers" => "checked".b,
    "/large" => Random.new(3).bytes(300_000)
  }.freeze

  def test_a_get_read_whole
    answering(BODIES) do |port|
      h3_connect(port) do |session|
        client = Threaded::HTTP3::Client.new(session)
        response = client.get("/hello")
        assert_equal [200, [["content-length", "11"]], "hello world", []], [response.status, response.headers, response.body, response.trailers]
        assert_equal BODIES.fetch("/large"), client.get("/large").body
        assert_equal [404, ""], client.get("/missing").then { [_1.status, _1.body] }
      end
    end
  end

  def test_an_informational_response_and_trailers
    answering(BODIES) do |port|
      h3_connect(port) do |session|
        client = Threaded::HTTP3::Client.new(session)
        assert_equal [200, "after a hint"], client.get("/early").then { [_1.status, _1.body] }
        assert_equal [["x-checksum", "abc"]], client.get("/trailers").trailers
      end
    end
  end

  def test_a_request_the_server_cancels
    answering(BODIES) do |port|
      h3_connect(port) do |session|
        error = assert_raises(Runtime::HTTP3::StreamReset) { Threaded::HTTP3::Client.new(session).get("/reset") }
        assert_equal HTTP3::ErrorCode::REQUEST_CANCELLED, error.error_code
      end
    end
  end

  # A request's body, a String or what reads as an IO does, goes as the
  # server takes it, a megabyte held back by flow control both ways.
  def test_a_request_with_a_body
    answering(BODIES) do |port|
      h3_connect(port) do |session|
        client = Threaded::HTTP3::Client.new(session)
        assert_equal "posted", client.request("POST", "/echo", body: "posted").body
        large = Random.new(4).bytes(1_000_000)
        assert_equal large, client.request("PUT", "/echo", body: StringIO.new(large)).body
      end
    end
  end

  # A block takes the response as it comes, its trailers after its body.
  def test_a_response_as_it_comes
    answering(BODIES) do |port|
      h3_connect(port) do |session|
        client = Threaded::HTTP3::Client.new(session)
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

  # A response cancelled, or left unread by its block, stops; the
  # connection goes on.
  def test_a_response_cancelled
    answering(BODIES) do |port|
      h3_connect(port) do |session|
        client = Threaded::HTTP3::Client.new(session)
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

  def test_a_priority
    answering(BODIES) do |port|
      h3_connect(port) do |session|
        client = Threaded::HTTP3::Client.new(session)
        assert_equal "u=1, i", client.request("GET", "/priority", urgency: 1, incremental: true).body
        assert_equal "none", client.get("/priority").body
        assert_raises(ArgumentError) { client.request("GET", "/priority", urgency: 8) }
      end
    end
  end

  # A client offering more than "h3", given another: HTTP/3 does not go
  # over it.
  def test_another_alpn
    server = server_owner
    tls = TLSPair.client_config(profile: TLS::Profile::QUIC, alpn: ["h3", *ALPN], registry: REGISTRY)
    error = Threaded::Client.connect("127.0.0.1", server.port, config: QUIC::Config.new, tls_config: tls, keyring: client_keyring(config: tls),
      server_name: "localhost") do |session|
      assert_equal ALPN.first, session.handshake&.alpn
      assert_raises(QUIC::ClosedError) { Threaded::HTTP3::Client.new(session).get("/hello") }
    end
    assert_equal [HTTP3::ErrorCode::GENERAL_PROTOCOL_ERROR, true], [error.error.code, error.error.application]
  ensure
    server&.driver&.stop
  end

  # A connection of HTTP/3 closes with H3_NO_ERROR once the block is over.
  def test_the_connection_closes_with_h3_no_error
    answering(BODIES) do |port, sessions|
      h3_connect(port) { |session| Threaded::HTTP3::Client.new(session).get("/hello") }
      session = sessions.pop
      assert eventually { session.closed? }
      assert_equal [HTTP3::ErrorCode::NO_ERROR, true], session.connection.close_reason.then { [_1.code, _1.application] }
    end
  end

  # A response the server sent just before it closed is still read.
  def test_a_response_that_comes_with_the_close
    answering(BODIES) do |port|
      h3_connect(port) { |session| assert_equal "last words", Threaded::HTTP3::Client.new(session).get("/last").body }
    end
  end

  # Requests HTTP/3 does not take give their streams up.
  def test_requests_not_taken_give_their_streams_up
    answering(BODIES) do |port|
      h3_connect(port) do |session|
        client = Threaded::HTTP3::Client.new(session)
        120.times { assert_raises(ArgumentError) { client.get("/hello", headers: [["X-Upper", "case"]]) } }
        assert_equal "hello world", client.get("/hello").body
      end
    end
  end

  # One client of one connection takes requests from many threads at once,
  # each answered with its own body.
  def test_requests_from_many_threads_at_once
    answering(BODIES) do |port|
      h3_connect(port) do |session|
        client = Threaded::HTTP3::Client.new(session)
        paths = %w[/hello /large /early /trailers] * 4
        bodies = paths.map { |path| Thread.new { client.get(path).body } }.map(&:value)
        assert_equal paths.map { BODIES.fetch(_1) }, bodies
      end
    end
  end

  # A Session of the runtime of fibers is not taken by the client on
  # threads, nor one on threads by the client of fibers: whichever took it
  # would touch the core with no lock taken.
  def test_the_runtimes_are_not_mixed
    fiber_session = Runtime::Session.new(Object.new, nil, role: :client)
    assert_raises(Runtime::Error::Usage) { Threaded::HTTP3::Client.new(fiber_session) }
    lock = Monitor.new
    threaded_session = Threaded::Session.new(Object.new, lock, role: :client, threads: Threaded::Threads.new(1))
    assert_raises(Runtime::Error::Usage) { Runtime::HTTP3::Client.new(threaded_session) }
  end
end
