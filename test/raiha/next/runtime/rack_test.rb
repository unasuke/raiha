require "raiha/next/test_helper"
require "raiha/next/support/runtime_http3"
require "raiha/next/runtime/rack"
require "async"
require "rack"
require "rack/lint"

# Rack 3 over the HTTP/3 server of the runtime, each application wrapped in
# Rack::Lint: the env of a request, a body that answers `each`, a
# streaming body, rack.input read as it comes, and the request itself in
# raiha.request.
class RaihaNextRuntimeRackTest < Minitest::Test
  include NextRuntimeHTTP3

  def serving(app)
    tls = h3_server_config
    server = Runtime::HTTP3::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1",
      port: 0)
    running = Fiber.schedule { server.run(&Runtime::Rack.new(Rack::Lint.new(app))) }
    sleep 0.01 until server.local_address
    yield server.local_address.fetch(1)
  ensure
    server&.stop(timeout: 1)
    sleep 0.01 while running&.alive?
  end

  def client(port, &) = h3_connect(port) { |session| yield Runtime::HTTP3::Client.new(session) }

  def test_the_env_and_a_body_of_each
    env = nil
    app = lambda do |given|
      env = given.reject { |key, _| key.start_with?("rack.lint") }
      [200, { "content-type" => "text/plain", "x-multi" => %w[a b], "rack.hidden" => "x" }, ["at ", given["PATH_INFO"], " ", given["QUERY_STRING"]]]
    end
    Sync do
      serving(app) do |port|
        response = client(port) { _1.get("/path?x=1", headers: [["accept", "*/*"], ["cookie", "a=1"], ["cookie", "b=2"]]) }
        assert_equal [200, "at /path x=1"], [response.status, response.body]
        assert_equal [["content-type", "text/plain"], ["x-multi", "a"], ["x-multi", "b"]], response.headers
      end
    end
    assert_equal ["GET", "", "/path", "x=1", "localhost", "443", "HTTP/3", "localhost", "https", "*/*", "a=1; b=2"],
      env.values_at("REQUEST_METHOD", "SCRIPT_NAME", "PATH_INFO", "QUERY_STRING", "SERVER_NAME", "SERVER_PORT", "SERVER_PROTOCOL", "HTTP_HOST",
        "rack.url_scheme", "HTTP_ACCEPT", "HTTP_COOKIE")
    assert_kind_of Runtime::HTTP3::Request, env["raiha.request"]
  end

  # A field named with an underscore is not taken for the one with a hyphen,
  # nor a host field added to HTTP_HOST.
  def test_fields_that_would_be_taken_for_others
    env = nil
    app = lambda do |given|
      env = given
      [200, {}, []]
    end
    Sync do
      serving(app) do |port|
        client(port) { _1.get("/", headers: [["x_forwarded_for", "10.0.0.1"], ["x-forwarded-for", "192.0.2.1"], ["host", "localhost"]]) }
      end
    end
    assert_equal ["192.0.2.1", "localhost", "localhost"], env.values_at("HTTP_X_FORWARDED_FOR", "HTTP_HOST", "SERVER_NAME")
  end

  # Content-Length given twice the same is one number.
  def test_a_content_length_given_twice
    env = nil
    app = lambda do |given|
      env = given
      [200, {}, [given["rack.input"].read]]
    end
    Sync do
      serving(app) do |port|
        assert_equal "hello", client(port) { _1.request("POST", "/", body: "hello", headers: [["content-length", "5"], ["content-length", "5"]]).body }
      end
    end
    assert_equal "5", env["CONTENT_LENGTH"]
  end

  # rack.input read by lines and as a whole, a megabyte of it.
  def test_rack_input
    app = lambda do |env|
      input = env["rack.input"]
      [200, {}, ["#{input.gets.inspect} #{input.read.bytesize} #{input.read.inspect}"]]
    end
    Sync do
      serving(app) do |port|
        body = "first line\n" + "x" * 1_000_000
        assert_equal "\"first line\\n\" 1000000 \"\"", client(port) { _1.request("POST", "/", body:, headers: [["content-type", "text/plain"]]).body }
      end
    end
  end

  # A streaming body is called with a stream that reads the request and
  # writes the response.
  def test_a_streaming_body
    app = lambda do |_env|
      [200, {}, lambda do |stream|
        stream << "echo: " << stream.read
        stream.close
      end]
    end
    Sync do
      serving(app) do |port|
        assert_equal "echo: streamed", client(port) { _1.request("PUT", "/", body: "streamed").body }
      end
    end
  end

  # A streaming body closed for writing has its response whole while it
  # goes on, and writes no more.
  def test_a_streaming_body_closed_for_writing
    release = Thread::Queue.new
    raised = nil
    app = lambda do |_env|
      [200, {}, lambda do |stream|
        (stream << "whole").close_write
        release.pop
        raised = assert_raises(IOError) { stream << "more" }
        stream.close
      end]
    end
    Sync do |task|
      serving(app) do |port|
        assert_equal "whole", task.with_timeout(5) { client(port) { _1.get("/").body } }
      ensure
        release << true
      end
    end
    assert raised
  end

  def test_a_head_has_no_body
    app = ->(_env) { [200, { "content-length" => "5" }, []] }
    Sync do
      serving(app) do |port|
        assert_equal [200, ""], client(port) { _1.request("HEAD", "/").then { |response| [response.status, response.body] } }
      end
    end
  end

  # What a streaming body writes to a response to HEAD goes nowhere.
  def test_a_head_has_no_body_however_it_streams
    app = ->(_env) { [200, {}, ->(stream) { (stream << "hello").close }] }
    Sync do
      serving(app) do |port|
        assert_equal [200, ""], client(port) { _1.request("HEAD", "/").then { |response| [response.status, response.body] } }
      end
    end
  end
end
