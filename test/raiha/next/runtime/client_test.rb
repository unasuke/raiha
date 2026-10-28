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

  def test_a_scheduler_is_needed
    assert_raises(Runtime::Error::Usage) { Runtime::Client.connect("127.0.0.1", free_port, **options) { flunk } }
  end
end
