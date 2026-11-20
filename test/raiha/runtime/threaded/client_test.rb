require "test_helper"
require "support/threaded_owner"

# The client of the runtime on threads against a server on threads on the
# loopback interface: a Session for the block in the thread that called
# it, the next address after one that does not answer in time, every
# failure told when none does, and the threads of its streams waited for.
class RaihaRuntimeThreadedClientTest < Minitest::Test
  include ThreadedOwner

  # A client that tries the addresses it is given instead of a name's, and
  # keeps the driver of each attempt.
  class Addressed < Threaded::Client
    attr_reader :drivers

    def initialize(addresses, **)
      super(**)
      @addresses = addresses
      @drivers = []
    end

    private def attempt(...)
      super.tap { |driver, _session| @drivers << driver }
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

  def echo(server)
    Thread.new do
      accepted(server).each_stream do |stream|
        stream << stream.read
        stream.close_write
      end
    end
  end

  def test_a_session_for_the_block
    server = server_owner
    echo(server)
    value = Threaded::Client.connect("127.0.0.1", server.port, server_name: "localhost", **options) do |session|
      assert_nil Fiber.scheduler
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

  SEED = "\x1d".b * 32

  # A server's Owner that gives tickets, which allow `max_early_data_size`
  # of 0-RTT, and the address_validated of each first Initial it takes. It
  # takes `hold` seconds over each ClientHello, so that a client's 0-RTT
  # goes before the server's flight comes. With `warmup`, it rejects all
  # 0-RTT.
  def resuming_server(max_early_data_size: 0, hold: 0, warmup: false)
    anti_replay = TLS::AntiReplay::Memory.new(now: Time.now, warmup:) if max_early_data_size.positive?
    tls = server_config(ticket_key: SEED, max_early_data_size:)
    keyring = server_keyring(config: tls)
    endpoint, server = owner(:server, QUIC::Config.new, tls_config: tls, keyring:)
    validated = []
    server.define_singleton_method(:route) do |route, now|
      validated << route.address_validated if route.is_a?(QUIC::Route::Incoming)
      sleep hold if route.is_a?(QUIC::Route::ClientHello)
      case route
      when QUIC::Route::Incoming then (hello = endpoint.admit(route.handle, now:)) && route(hello, now)
      when QUIC::Route::ClientHello
        add(endpoint.accept(route.handle, tls_config: tls, keyring:, anti_replay:, now:))
      end
    end
    server.driver.start
    [server, validated]
  end

  # A ticket and a token a first connection was given, once it has them.
  def ticket_and_token(port)
    Threaded::Client.connect("127.0.0.1", port, server_name: "localhost", **options) do |session|
      session.wait_for(deadline: Threaded::Driver.clock + 2) { session.tokens.first && session.tickets.first }
      [session.tickets.last, session.tokens.last]
    end
  end

  # A second connection resumes the ticket of the first, and with its token
  # comes from an address the server need not validate.
  def test_a_resumption
    server, validated = resuming_server
    ticket, token = ticket_and_token(server.port)
    resumed = Threaded::Client.connect("127.0.0.1", server.port, server_name: "localhost", session: ticket, token:, **options) do |session|
      session.handshake&.resumed
    end
    assert resumed
    assert_equal [false, true], validated
  ensure
    server&.driver&.stop
  end

  # Echoes each stream of the server's `index`th connection, and gives
  # whether each came in 0-RTT.
  def echo_early(server, index)
    early = []
    Thread.new do
      sleep 0.01 until (accepted = server.sessions[index])
      accepted.each_stream do |stream|
        early << accepted.connection.stream_early_data?(stream.id)
        stream << stream.read
        stream.close_write
      end
    end
    early
  end

  # With early_data: true, the block is given the Session before the
  # handshake completes, and what it writes first goes in 0-RTT.
  def test_0rtt
    server, = resuming_server(max_early_data_size: 16_384, hold: 0.05)
    ticket, = ticket_and_token(server.port)
    early = echo_early(server, 1)
    echoed = Threaded::Client.connect("127.0.0.1", server.port, server_name: "localhost", session: ticket, early_data: true,
      **options) do |session|
      refute session.connection.handshake_complete?
      stream = session.open_stream
      stream << "early"
      stream.close_write
      [stream.read, session.connection.zero_rtt_state]
    end
    assert_equal ["early", :accepted], echoed
    assert eventually { early.any? }
    assert_equal [true], early
  ensure
    server&.driver&.stop
  end

  # A server that takes no 0-RTT: a stream the block opened in it raises
  # Error::ZeroRttRejected from then on, in a read that waited on it in
  # another thread as well, and one opened after takes the same ID.
  def test_0rtt_rejected
    server, = resuming_server(max_early_data_size: 16_384, hold: 0.05, warmup: true)
    ticket, = ticket_and_token(server.port)
    early = echo_early(server, 1)
    result = Threaded::Client.connect("127.0.0.1", server.port, server_name: "localhost", session: ticket, early_data: true,
      **options) do |session|
      stream = session.open_stream
      stream << "early"
      waiting = Thread.new do
        stream.read
      rescue QUIC::Error::ZeroRttRejected => error
        error
      end
      session.wait_handshake
      assert_kind_of QUIC::Error::ZeroRttRejected, waiting.value
      assert_raises(QUIC::Error::ZeroRttRejected) { stream.close_write }
      again = session.open_stream
      again << "again"
      again.close_write
      [again.id == stream.id, again.read, session.connection.zero_rtt_state]
    end
    assert_equal [true, "again", :rejected], result
    assert_equal [false], early
  ensure
    server&.driver&.stop
  end

  # What the block wrote last is acknowledged before the connection closes,
  # which closes with the application's error 0.
  def test_the_connection_closes_once_what_was_sent_is_acknowledged
    payload = Random.new(2).bytes(500_000)
    server = server_owner
    reading = Thread.new { accepted(server).accept_stream.read }
    Threaded::Client.connect("127.0.0.1", server.port, server_name: "localhost", **options) do |session|
      stream = session.open_stream
      stream << payload
      stream.close_write
    end
    assert_equal payload, reading.value
    connection = accepted(server).connection
    assert eventually { connection.close_reason }
    assert_equal [0, true], [connection.close_reason.code, connection.close_reason.application]
  ensure
    server&.driver&.stop
  end

  def test_the_next_address_after_one_that_does_not_answer
    server = server_owner
    client = Addressed.new([["127.0.0.1", free_port], ["127.0.0.1", server.port]], connect_timeout: 0.2, **options)
    assert_equal :connected, client.connect("example.test", 443, server_name: "localhost") { :connected }
  ensure
    server&.driver&.stop
  end

  def test_no_address_answers
    addresses = [["127.0.0.1", free_port], ["127.0.0.1", free_port]]
    client = Addressed.new(addresses, connect_timeout: 0.1, **options)
    error = assert_raises(Runtime::ConnectError) { client.connect("example.test", 443, server_name: "localhost") { flunk } }
    assert_equal addresses, error.errors.map(&:first)
    assert_equal [["no handshake in 0.1 seconds", false]] * 2, error.errors.map { |_, closed| [closed.error.reason, closed.error.application] }
    threads = client.drivers.flat_map { |driver| [*driver.instance_variable_get(:@readers), driver.instance_variable_get(:@runner)] }
    assert_equal [false] * 4, threads.map(&:alive?)
  end

  def test_a_name_that_does_not_resolve
    error = assert_raises(Runtime::ConnectError) { Addressed.new([], **options).connect("nowhere.test", 443) { flunk } }
    assert_equal [["nowhere.test", SocketError]], error.errors.map { |address, failure| [address, failure.class] }
  end

  # A connect left by an exception from outside, Interrupt say, leaves no
  # thread of its driver behind and the socket closed.
  def test_a_connect_left_from_outside
    client = Addressed.new([["127.0.0.1", free_port]], **options)
    connecting = Thread.new do
      client.connect("example.test", 443, server_name: "localhost") { flunk }
    rescue Interrupt
      :interrupted
    end
    sleep 0.05
    connecting.raise(Interrupt)
    assert_equal :interrupted, connecting.value
    driver = client.instance_variable_get(:@driver)
    assert driver.stopped?
    assert driver.instance_variable_get(:@udp).closed?
    refute driver.instance_variable_get(:@runner).alive?
  end

  # Once the block is over, the threads of the streams are waited for.
  def test_the_threads_of_the_streams_are_waited_for
    server = server_owner
    done = []
    started = Queue.new
    Threaded::Client.connect("127.0.0.1", server.port, server_name: "localhost", **options) do |session|
      Thread.new do
        stream = accepted(server).open_stream
        (stream << "from the server").close_write
      end
      Thread.new do
        session.each_stream do |stream|
          started << true
          sleep 0.2
          done << stream.read
        end
      end
      started.pop
    end
    assert_equal ["from the server"], done
  ensure
    server&.driver&.stop
  end
end
