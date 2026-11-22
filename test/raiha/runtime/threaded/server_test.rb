require "test_helper"
require "support/threaded_owner"
require "json"
require "tmpdir"

# The server of the runtime on threads against the client on threads on the
# loopback interface: a Session for the block in a thread of each
# connection, no scheduler needed, the connection closed when the block is
# over or raises, handlers that block holding up no other connection, and
# no more threads than it is given.
class RaihaRuntimeThreadedServerTest < Minitest::Test
  include ThreadedOwner

  # A client on threads connected to `port`, its Session given to the
  # block. Raises Runtime::ConnectError when the server does not take it.
  def connect(port, &)
    tls = client_config
    Threaded::Client.connect("127.0.0.1", port, config: QUIC::Config.new, tls_config: tls, keyring: client_keyring(config: tls),
      server_name: "localhost", connect_timeout: 2, &)
  end

  # The code of the transport error that kept a client from connecting.
  def refused_with(error) = error.errors.first.last.error.code

  # What a stream of `session` answers to `data`.
  def echo(session, data)
    stream = session.open_stream
    stream << data
    stream.close_write
    stream.read
  end

  def echoes(session) = session.each_stream { |stream| (stream << "ECHO:" << stream.read).close_write }

  # A server on threads on a free port running `handler` for each session,
  # for the block, which is given the port, the server and the thread that
  # runs it; stopped after.
  def serving(handler, tls: server_config, config: QUIC::Config.new, **options)
    server = Threaded::Server.new(config:, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1", port: 0, **options)
    running = Thread.new { server.run(&handler) }
    sleep 0.01 until server.local_address
    yield server.local_address.fetch(1), server, running
  ensure
    server&.stop(timeout: 1)
    running&.join(10)
  end

  # The threads `server` started for the application, still running.
  def running_threads(server) = %i[@handlers @threads].sum { |name| server.instance_variable_get(name).running.size }

  # Runs the block with the threads it starts reporting no exception.
  def quietly
    report = Thread.report_on_exception
    Thread.report_on_exception = false
    yield
  ensure
    Thread.report_on_exception = report
  end

  def test_each_session_in_a_thread_of_its_own
    handled = Queue.new
    handler = lambda do |session|
      handled << [Thread.current.name, Fiber.scheduler]
      echoes(session)
    end
    serving(handler) do |port|
      replies = Array.new(3) { |i| Thread.new { connect(port) { |session| echo(session, i.to_s) } } }.map(&:value)
      assert_equal %w[ECHO:0 ECHO:1 ECHO:2], replies
      assert_equal [["raiha-conn", nil]] * 3, 3.times.map { handled.pop }
    end
  end

  # The block is over: what it sent comes whole, and the connection closes
  # with the application's error 0.
  def test_a_block_that_returns_closes_its_connection
    serving(->(session) { (session.open_stream(direction: :uni) << "bye").close_write }) do |port|
      connect(port) do |session|
        assert_equal "bye", session.accept_stream.read
        assert eventually { session.closed? }
        error = assert_raises(QUIC::ClosedError) { session.open_stream }
        assert_equal [0, true], [error.error.code, error.error.application]
      end
    end
  end

  # The block raises: its connection closes with INTERNAL_ERROR, and the
  # server goes on serving.
  def test_a_block_that_raises_closes_only_its_connection
    quietly do
      handler = lambda do |session|
        stream = session.accept_stream
        raise "the handler fails" if stream.read == "fail"
        (stream << "ok").close_write
      end
      serving(handler) do |port|
        connect(port) do |session|
          (session.open_stream << "fail").close_write
          assert eventually { session.closed? }
          error = assert_raises(QUIC::ClosedError) { session.open_stream }
          assert_equal [QUIC::ErrorCode::INTERNAL_ERROR, false], [error.error.code, error.error.application]
        end
        assert_equal "ok", connect(port) { |session| echo(session, "fine") }
      end
    end
  end

  # A handler held up in what blocks its thread, a queue here, holds up no
  # other connection.
  def test_a_handler_that_blocks_holds_up_no_other
    held = Queue.new
    first = true
    handler = lambda do |session|
      if first
        first = false
        held.pop
      end
      echoes(session)
    end
    serving(handler) do |port|
      blocked = Thread.new { connect(port) { |session| echo(session, "held") } }
      sleep 0.1
      assert_equal "ECHO:free", connect(port) { |session| echo(session, "free") }
      held << true
      assert_equal "ECHO:held", blocked.value
    end
  end

  def test_no_more_connections_than_it_takes
    serving(method(:echoes), max_connections: 1) do |port|
      connect(port) do |session|
        assert_equal "ECHO:a", echo(session, "a")
        error = assert_raises(Runtime::ConnectError) { connect(port) { nil } }
        assert_equal QUIC::ErrorCode::CONNECTION_REFUSED, refused_with(error)
      end
    end
  end

  # A handler held up after its connection has closed keeps its place:
  # with one place, the next client is refused until the handler ends.
  def test_a_handler_counts_until_its_thread_ends
    held = Queue.new
    serving(->(_session) { held.pop }, max_connections: 1) do |port, server|
      connect(port) { |session| session.close(error_code: 0) }
      assert eventually { server.instance_variable_get(:@sessions).empty? }
      error = assert_raises(Runtime::ConnectError) { connect(port) { nil } }
      assert_equal QUIC::ErrorCode::CONNECTION_REFUSED, refused_with(error)
      held << true
      assert eventually { server.instance_variable_get(:@handlers).taken.zero? }
      held << true
      assert_equal :taken, connect(port) { :taken }
    end
  end

  # The threads of the streams are `max_threads` at most, however many
  # streams the client opens at once.
  def test_no_more_stream_threads_than_max_threads
    most = 0
    lock = Mutex.new
    now = 0
    handler = lambda do |session|
      session.each_stream do |stream|
        lock.synchronize { most = [most, now += 1].max }
        sleep 0.02
        lock.synchronize { now -= 1 }
        (stream << stream.read).close_write
      end
    end
    serving(handler, max_threads: 3) do |port|
      connect(port) do |session|
        streams = Array.new(12) { |i| (session.open_stream << i.to_s).tap(&:close_write) }
        assert_equal Array.new(12) { _1.to_s }, streams.map(&:read)
      end
    end
    assert_equal 3, most
  end

  def test_max_threads_is_a_positive_integer
    tls = server_config
    [0, -1, "1", nil].each do |max_threads|
      assert_raises(ArgumentError) { Threaded::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), max_threads:) }
    end
  end

  # A server asked to stop tells each session it is stopping, and returns
  # from `run` once the sessions have ended their connections, with no
  # thread it started still running.
  def test_stop_lets_the_sessions_end
    started = Queue.new
    handler = lambda do |session|
      started << true
      sleep 0.01 until session.stopping?
      (session.open_stream(direction: :uni) << "stopping").close_write
    end
    serving(handler) do |port, server, running|
      connect(port) do |session|
        started.pop
        server.stop(timeout: 5)
        assert_equal "stopping", session.accept_stream.read
      end
      assert running.join(5)
      assert_equal 0, running_threads(server)
    end
  end

  # A handler held up past the time `stop` gave is left running: `run`
  # returns all the same, with the socket closed.
  def test_a_handler_held_up_past_the_stop
    held = Queue.new
    started = Queue.new
    serving(->(_session) { started << true; held.pop }) do |port, server, running|
      connect(port) do
        started.pop
        started = Threaded::Driver.clock
        server.stop(timeout: 0.3)
        assert running.join(5)
        assert_operator Threaded::Driver.clock - started, :<, 3
        assert_equal 1, running_threads(server)
        assert server.instance_variable_get(:@udp).closed?
      end
      held << true
    end
  end

  # A signal handler may ask a server to stop.
  def test_stop_from_a_signal_handler
    serving(method(:echoes)) do |port, server, running|
      previous = Signal.trap("USR2") { server.stop(timeout: 1) }
      connect(port) { |session| assert_equal "ECHO:a", echo(session, "a") }
      Process.kill("USR2", Process.pid)
      assert running.join(5)
    ensure
      Signal.trap("USR2", previous || "DEFAULT")
    end
  end

  # The qlog files, written outside the core lock while connections come
  # and go and as the server stops, read as JSON Text Sequences.
  def test_the_qlog_as_it_stops
    Dir.mktmpdir do |dir|
      serving(method(:echoes), qlog_dir: dir) do |port, server, running|
        Array.new(4) { |i| Thread.new { connect(port) { |session| echo(session, i.to_s * 1000) } } }.each(&:join)
        server.stop(timeout: 1)
        running.join(5)
      end
      files = Dir[File.join(dir, "*_server.sqlog")]
      assert_equal 4, files.size
      files.each do |path|
        records = File.binread(path).split("\x1e").reject(&:empty?).map { JSON.parse(_1) }
        assert_includes records.map { _1["name"] }, "quic:packet_received"
      end
    end
  end
end
