require "test_helper"
require "support/threaded_owner"
require "support/draining_connection"
require "monitor"

# A Session of the runtime on threads between a client and a server on
# the loopback interface: streams read and written as an IO would be from
# any thread, waiting on the peer's flow control and stream limits, and
# what the peer resets, stops or closes raised where the application waits.
class RaihaRuntimeThreadedSessionTest < Minitest::Test
  include ThreadedOwner

  # A client's Session and the server's Owner, connected, for the block.
  def connected(server: QUIC::Config.new, client: QUIC::Config.new, server_tls: server_config, max_threads: 64)
    server_owner = server_owner(server, tls: server_tls, max_threads:)
    endpoint, client_owner = owner(:client, client)
    tls = client_config
    connection = endpoint.connect(tls_config: tls, keyring: client_keyring(config: tls), server_name: "localhost",
      remote: ["127.0.0.1", server_owner.port], now: Threaded::Driver.clock)
    client_owner.add(connection)
    client_owner.driver.start
    yield client_owner.sessions.first, server_owner
  ensure
    client_owner&.driver&.stop
    server_owner&.driver&.stop
    [client_owner, server_owner].each { _1&.driver&.join }
  end

  def test_no_scheduler
    connected do |client, server_owner|
      scheduler = :unset
      Thread.new { accepted(server_owner).each_stream { |stream| scheduler = Fiber.scheduler; stream.read } }
      (client.open_stream << "x").close_write
      assert eventually { scheduler != :unset }
      assert_nil scheduler
    end
  end

  # Holds the reads of the server back to 16 KiB, so a write of a megabyte
  # waits for room again and again.
  def test_an_echo_held_back_by_flow_control
    payload = Random.new(1).bytes(1_000_000)
    connected(server: QUIC::Config.new(initial_max_stream_data_bidi_remote: 16_384, initial_max_data: 65_536)) do |client, server_owner|
      Thread.new do
        stream = accepted(server_owner).accept_stream
        data = stream.read
        stream << "ECHO:" << data
        stream.close_write
      end
      stream = client.open_stream
      stream.write(payload)
      stream.close_write
      assert_equal "ECHO:".b + payload, stream.read
      assert_nil stream.read(1)
    end
  end

  # A write the peer's flow control holds back waits for room, and the
  # driver goes round only as datagrams and timers come.
  def test_a_write_held_back_does_not_spin
    connected(server: QUIC::Config.new(initial_max_stream_data_bidi_remote: 1_000)) do |client, _server_owner|
      stream = client.open_stream
      writer = Thread.new { stream.write("x" * 100_000) }
      owner = client.instance_variable_get(:@driver).instance_variable_get(:@owner)
      sleep 0.1
      before = owner.turns
      sleep 0.3
      assert_operator owner.turns - before, :<, 30
      writer.kill
    end
  end

  # The application's thread resets a stream through the connection, which
  # takes the core lock for it.
  def test_a_stream_the_peer_resets
    connected do |client, server_owner|
      stream = client.open_stream
      stream.write("hello")
      server = accepted(server_owner)
      Thread.new do
        server.accept_stream.write("partial")
        server.connection.stream_reset(stream.id, error_code: 7)
        server.changed
      end
      error = assert_raises(Runtime::StreamReset) { stream.read }
      assert_equal [stream.id, 7], [error.stream_id, error.error_code]
    end
  end

  def test_a_stream_the_peer_stops
    connected do |client, server_owner|
      stream = client.open_stream
      stream.write("hello")
      server = accepted(server_owner)
      server.connection.stream_stop_sending(server.accept_stream.id, error_code: 9)
      server.changed
      error = assert_raises(Runtime::StreamReset) { loop { stream.write("x" * 1024) } }
      assert_equal 9, error.error_code
    end
  end

  # A peer that allows one stream at a time: the second open waits until
  # the first is over at both ends.
  def test_an_open_waits_for_the_peers_limit
    connected(server: QUIC::Config.new(initial_max_streams_bidi: 1)) do |client, server_owner|
      first = client.open_stream
      opened = nil
      Thread.new { opened = client.open_stream }
      sleep 0.05
      assert_nil opened
      first.close_write
      Thread.new do
        stream = accepted(server_owner).accept_stream
        stream.read
        stream.close_write
      end
      assert_equal "", first.read
      assert eventually { opened }
      assert_equal 4, opened.id
    end
  end

  # Streams opened and ended one after another leave nothing behind at
  # either end, however many there were.
  def test_streams_over_are_forgotten
    connected do |client, server_owner|
      Thread.new do
        accepted(server_owner).each_stream do |stream|
          data = stream.read
          stream << data
          stream.close_write
        end
      end
      200.times do |i|
        stream = client.open_stream
        stream << i.to_s
        stream.close_write
        assert_equal i.to_s, stream.read
      end
      server = accepted(server_owner)
      assert eventually { server.instance_variable_get(:@tracks).empty? }
      assert_empty client.instance_variable_get(:@tracks)
      assert_equal [200, 0, 0, 0], server.instance_variable_get(:@peer_next)
    end
  end

  # A driver that stops wakes what waits on its sessions, with what failed
  # in it when something did.
  def test_the_driver_stops
    connected do |client, server_owner|
      stream = client.open_stream
      stream.write("hello")
      server = accepted(server_owner)
      reading = Thread.new do
        assert_raises(RuntimeError, "a turn that fails") { server.accept_stream.read }
      end
      server_owner.driver.send(:fail, RuntimeError.new("a turn that fails"))
      reading.join
      client.instance_variable_get(:@driver).stop
      error = assert_raises(Raiha::QUIC::ClosedError) { stream.read }
      assert_equal "the runtime stopped", error.error.reason
      assert client.closed?
    end
  end

  # What waits when the peer closes raises the error it closed with, and
  # what comes after does too; the server's streams stop coming. The
  # stream sends nothing, so that none comes to the server before it
  # closes, as a thread closing it runs later than a fiber would.
  def test_the_peer_closes
    connected do |client, server_owner|
      stream = client.open_stream
      server = accepted(server_owner)
      Thread.new { server.close(error_code: 42, reason: "bye") }
      error = assert_raises(Raiha::QUIC::ClosedError) { stream.read }
      assert_equal [42, true, "bye"], [error.error.code, error.error.application, error.error.reason]
      assert_raises(Raiha::QUIC::ClosedError) { client.open_stream }
      assert client.closed?
      assert_nil server.accept_stream
    end
  end

  # A protocol attached once the peer has closed is not, and raises: a
  # handler's thread may come to it after the close.
  def test_an_attach_once_closed
    connected do |client, server_owner|
      server = accepted(server_owner)
      server.close(error_code: 3)
      assert eventually { client.closed? }
      error = assert_raises(Raiha::QUIC::ClosedError) { client.attach(Object.new) }
      assert_equal 3, error.error.code
      assert_nil client.instance_variable_get(:@protocol)
    end
  end

  def test_tickets_and_tokens
    connected(server_tls: server_config(ticket_key: "\x1c".b * 32)) do |client, _server_owner|
      client.wait_for(deadline: Threaded::Driver.clock + 2) { client.tokens.first && client.tickets[1] }
      assert_equal [QUIC::Session, QUIC::Session], client.tickets.map(&:class)
      assert_equal 1, client.tokens.size
    end
  end

  # Many threads open streams on one connection at once and read and write
  # each, and every echo comes back whole.
  def test_streams_from_many_threads_at_once
    connected do |client, server_owner|
      Thread.new { accepted(server_owner).each_stream { |stream| (stream << stream.read).close_write } }
      echoed = 16.times.map do |i|
        Thread.new do
          payload = Random.new(i).bytes(50_000)
          stream = client.open_stream
          stream.write(payload)
          stream.close_write
          stream.read == payload
        end
      end.map(&:value)
      assert_equal [true] * 16, echoed
    end
  end

  # A thread reading one stream does not keep the reset of another from the
  # thread that waits on it, however the events of the turn fall to them.
  def test_a_reset_while_another_stream_is_read
    connected do |client, server_owner|
      quiet = client.open_stream
      quiet.write("quiet")
      reset = client.open_stream
      reset.write("reset")
      server = accepted(server_owner)
      streams = 2.times.map { server.accept_stream }
      reading = Thread.new { quiet.read }
      waiting = Thread.new { assert_raises(Runtime::StreamReset) { reset.read }.error_code }
      sleep 0.05
      server.connection.stream_reset(streams.last.id, error_code: 3)
      server.changed
      assert_equal 3, waiting.value
      assert reading.alive?
      reading.kill
    end
  end

  # With two places, the third stream waits for one of the first two to
  # end; a place taken when no stream came goes back.
  def test_each_stream_waits_for_a_place
    connected(max_threads: 2) do |client, server_owner|
      release = Queue.new
      running = Queue.new
      Thread.new do
        accepted(server_owner).each_stream do |stream|
          running << stream.id
          release.pop
          (stream << stream.read).close_write
        end
      end
      streams = 3.times.map { (client.open_stream << "x").tap(&:close_write) }
      assert_equal [0, 4], 2.times.map { running.pop }.sort
      sleep 0.1
      assert_equal 0, running.size
      release << true
      assert_equal 8, running.pop
      2.times { release << true }
      assert_equal %w[x x x], streams.map(&:read)
      assert eventually { server_owner.threads.taken == 1 }
    end
  end

  # When the connection closes, what waits for a place stops waiting, and
  # the place taken for a stream that never came goes back.
  def test_the_wait_for_a_place_ends_with_the_connection
    connected(max_threads: 1) do |client, server_owner|
      release = Queue.new
      each = Thread.new { accepted(server_owner).each_stream { |_stream| release.pop } }
      (client.open_stream << "x").close_write
      assert eventually { server_owner.threads.taken == 1 }
      (client.open_stream << "y").close_write
      sleep 0.05
      client.close(error_code: 0)
      assert each.join(5)
      release << true
      assert eventually { server_owner.threads.taken.zero? }
    end
  end

  # Code of the application called holding the core lock, as each_stream
  # from inside the block of wait_for is, raises: it would keep the driver
  # from running while it waits.
  def test_the_application_holding_the_lock
    connected do |client, _server_owner|
      assert_raises(Runtime::Error::Usage) { client.wait_for { client.each_stream { nil } } }
    end
  end

  # A connection that gives the events it is made with.
  class Events
    def initialize(events) = @events = events

    def each_event(&) = @events.shift(@events.size).each(&)
  end

  class Recorder
    attr_reader :values

    def initialize = @values = []

    def tls_trace(value) = @values << value
  end

  # A server that gives more tickets and tokens than are kept: the oldest
  # go, and each ticket dropped is traced.
  def test_the_newest_tickets_and_tokens_are_kept
    count = Threaded::Session::MAX_HELD + 2
    sessions = Array.new(count) { QUIC::Session.new(tls: nil, transport_parameters: nil, alpn: nil, version: _1) }
    tokens = Array.new(count) { "token#{_1}" }
    events = sessions.map { QUIC::Event::SessionTicket.new(session: _1) } + tokens.map { QUIC::Event::NewToken.new(token: _1) }
    tracer = Recorder.new
    connection = Events.new(events)
    def connection.close_reason = nil
    # A Monitor stands for the driver: the core lock, its conditions.
    lock = Monitor.new
    session = Threaded::Session.new(connection, lock, role: :client, threads: Threaded::Threads.new(1), tracer:)
    lock.synchronize { session.turn }
    assert_equal sessions.last(Threaded::Session::MAX_HELD), session.tickets
    assert_equal tokens.last(Threaded::Session::MAX_HELD), session.tokens
    assert_equal [TLS::Trace::TicketIgnored.new(reason: :too_many_tickets)] * 2, tracer.values
  end

  # What is acknowledged slower than three PTOs, while more of it keeps
  # being acknowledged, is waited for whole before the connection closes.
  def test_a_close_waits_while_more_is_acknowledged
    connection = DrainingConnection.new(4, 0.05)
    driver = Monitor.new
    def driver.changed = nil
    started = Threaded::Driver.clock
    Threaded::Session.new(connection, driver, role: :client, threads: Threaded::Threads.new(1)).close_when_acknowledged
    assert_equal [0, 0], connection.closed_with
    assert_operator Threaded::Driver.clock - started, :>=, 0.15
  end

  # A peer that takes what was sent a little at a time is waited for no
  # longer than the timeout in all, though more keeps being acknowledged.
  def test_a_close_waits_no_longer_than_its_timeout
    connection = DrainingConnection.new(1_000, 0.05)
    driver = Monitor.new
    def driver.changed = nil
    started = Threaded::Driver.clock
    Threaded::Session.new(connection, driver, role: :client, threads: Threaded::Threads.new(1)).close_when_acknowledged(timeout: 0.3)
    assert_equal 0, connection.closed_with.first
    assert_operator connection.closed_with.last, :>, 0
    assert_operator Threaded::Driver.clock - started, :<, 1
  end
end
