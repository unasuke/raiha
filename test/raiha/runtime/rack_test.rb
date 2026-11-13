require "test_helper"
require "support/runtime_http3"
require "raiha/runtime/rack"
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

  # An authority of http with no port is of port 80, of https of 443.
  def test_the_port_of_a_scheme
    request = Struct.new(:method, :path, :authority, :scheme, :protocol, :headers, :body) do
      def respond(*) = nil
    end
    envs = %w[http https].map do |scheme|
      env = nil
      Runtime::Rack.new(->(given) { (env = given) && [200, {}, []] }).call(request.new("GET", "/", "example.com", scheme, nil, [], nil))
      env.values_at("SERVER_NAME", "SERVER_PORT", "rack.url_scheme")
    end
    assert_equal [["example.com", "80", "http"], ["example.com", "443", "https"]], envs
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

  # A Rack application served by workers, each in a Ractor of its own: an
  # application built in each, which the Ractor can run.
  def test_served_by_workers
    skip "SO_REUSEPORT spreads datagrams on Linux alone" unless RUBY_PLATFORM.include?("linux")
    tls = h3_server_config
    workers = Runtime::Workers.new(count: 2, config: QUIC::Config.new, host: "127.0.0.1", port: 0,
      args: [tls, Ractor.make_shareable(NextTLSPair.server_identity)]) do |worker, tls, identity|
      keyring = Raiha::TLS::Keyring.server(config: tls, identities: [identity])
      app = ->(env) { [200, { "content-type" => "text/plain" }, ["worker #{worker.id} at #{env["PATH_INFO"]}"]] }
      Sync do
        Raiha::Runtime::HTTP3::Server.new(config: worker.config, tls_config: tls, keyring:, worker:)
          .run(&Raiha::Runtime::Rack.new(app))
      end
    end
    running = Thread.new { workers.run }
    sleep 0.01 until workers.local_address || !running.alive?
    Sync do
      response = client(workers.local_address.fetch(1)) { _1.get("/rack") }
      assert_equal 200, response.status
      assert_match(/\Aworker [01] at \/rack\z/, response.body)
    end
  ensure
    workers&.stop(timeout: 1)
    running&.join(10)
  end
end
