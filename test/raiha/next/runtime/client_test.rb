require "raiha/next/test_helper"
require "raiha/next/support/runtime_owner"
require "async"

# The client of the runtime against a server on the loopback interface: a
# Session for the block, the next address after one that does not answer
# in time, and every failure told when none does.
class RaihaNextRuntimeClientTest < Minitest::Test
  include NextRuntimeOwner

  # A client that tries the addresses it is given instead of a name's.
  class Addressed < Runtime::Client
    def initialize(addresses, **)
      super(**)
      @addresses = addresses
    end

    private def resolve(host, _port)
      raise SocketError, "#{host} does not resolve" if @addresses.empty?
      @addresses
    end
  end

  def options
    tls = client_config
    { config: QUIC::Config.new, tls_config: tls, keyring: client_keyring(config: tls) }
  end

  # A port nothing listens on.
  def free_port = UDPSocket.open { |socket| socket.bind("127.0.0.1", 0) && socket.addr[1] }

  def echo(server)
    Fiber.schedule do
      accepted(server).each_stream do |stream|
        stream << stream.read
        stream.close_write
      end
    end
  end

  def test_a_session_for_the_block
    Sync do
      server = server_owner
      echo(server)
      value = Runtime::Client.connect("127.0.0.1", server.port, server_name: "localhost", **options) do |session|
        assert session.connection.handshake_complete?
        stream = session.open_stream
        stream << "hello"
        stream.close_write
        stream.read
      end
      assert_equal "hello", value
    ensure
      server&.driver&.stop
    end
  end

  SEED = "\x1d".b * 32

  # A server's Owner that gives tickets, and the address_validated of each
  # first Initial it takes.
  def resuming_server
    server = server_owner(tls: server_config(ticket_key: SEED))
    validated = []
    server.define_singleton_method(:route) do |route, now|
      validated << route.address_validated if route.is_a?(QUIC::Route::Incoming)
      super(route, now)
    end
    [server, validated]
  end

  # A ticket and a token a first connection was given, once it has them.
  def ticket_and_token(port)
    Runtime::Client.connect("127.0.0.1", port, server_name: "localhost", **options) do |session|
      session.wait_for(deadline: Runtime::Driver.clock + 2) { session.tokens.first && session.tickets.first }
      [session.tickets.last, session.tokens.last]
    end
  end

  # A second connection resumes the ticket of the first, and with its
  # token comes from an address the server need not validate.
  def test_a_resumption
    Sync do
      server, validated = resuming_server
      ticket, token = ticket_and_token(server.port)
      resumed = Runtime::Client.connect("127.0.0.1", server.port, server_name: "localhost", session: ticket, token:, **options) do |session|
        session.handshake&.resumed
      end
      assert resumed
      assert_equal [false, true], validated
    ensure
      server&.driver&.stop
    end
  end

  # What the block wrote last is acknowledged before the connection closes,
  # and the connection closes with the application's error 0, not by
  # running out of idle time.
  def test_the_connection_closes_once_what_was_sent_is_acknowledged
    payload = Random.new(2).bytes(500_000)
    Sync do
      server = server_owner
      received = nil
      Fiber.schedule { received = accepted(server).accept_stream.read }
      Runtime::Client.connect("127.0.0.1", server.port, server_name: "localhost", **options) do |session|
        stream = session.open_stream
        stream << payload
        stream.close_write
      end
      sleep 0.01 until received
      assert_equal payload, received
      connection = accepted(server).connection
      sleep 0.01 until connection.close_reason
      assert_equal [0, true], [connection.close_reason.code, connection.close_reason.application]
    ensure
      server&.driver&.stop
    end
  end

  def test_the_next_address_after_one_that_does_not_answer
    Sync do
      server = server_owner
      client = Addressed.new([["127.0.0.1", free_port], ["127.0.0.1", server.port]], connect_timeout: 0.2, **options)
      assert_equal :connected, client.connect("example.test", 443, server_name: "localhost") { :connected }
    ensure
      server&.driver&.stop
    end
  end

  def test_no_address_answers
    addresses = [["127.0.0.1", free_port], ["127.0.0.1", free_port]]
    Sync do
      client = Addressed.new(addresses, connect_timeout: 0.1, **options)
      error = assert_raises(Runtime::ConnectError) { client.connect("example.test", 443, server_name: "localhost") { flunk } }
      assert_equal addresses, error.errors.map(&:first)
      assert_equal [["no handshake in 0.1 seconds", false]] * 2, error.errors.map { |_, closed| [closed.error.reason, closed.error.application] }
      assert_match(/\Acould not connect to example.test:443 \(\["127.0.0.1", \d+\]: closed with transport error 0x0: no handshake/, error.message)
    end
  end

  def test_a_name_that_does_not_resolve
    Sync do
      error = assert_raises(Runtime::ConnectError) { Addressed.new([], **options).connect("nowhere.test", 443) { flunk } }
      assert_equal [["nowhere.test", SocketError]], error.errors.map { |address, failure| [address, failure.class] }
    end
  end

  # The task of a connect stopped from outside leaves no fiber behind and
  # the socket closed.
  def test_a_connect_stopped_from_outside
    Sync do |task|
      client = Addressed.new([["127.0.0.1", free_port]], **options)
      connecting = task.async { client.connect("example.test", 443, server_name: "localhost") { flunk } }
      sleep 0.05
      connecting.stop
      sleep 0.01 until connecting.stopped?
      driver = client.instance_variable_get(:@session).instance_variable_get(:@driver)
      assert driver.stopped?
      assert driver.instance_variable_get(:@udp).closed?
    end
  end

  # What makes the connection fail before it starts, a Keyring for another
  # Config, leaves no socket behind.
  def test_an_attempt_that_cannot_start
    open = -> { ObjectSpace.each_object(UDPSocket).count { !_1.closed? } }
    Sync do
      before = open.call
      tls = client_config
      client = Addressed.new([["127.0.0.1", free_port]], config: QUIC::Config.new, tls_config: tls.with(alpn: ["h3"]),
        keyring: client_keyring(config: tls))
      assert_raises(ArgumentError) { client.connect("example.test", 443, server_name: "localhost") { flunk } }
      assert_equal before, open.call
    end
  end

  def test_a_scheduler_is_needed
    assert_raises(Runtime::Error::Usage) { Runtime::Client.connect("127.0.0.1", free_port, **options) { flunk } }
  end
end
