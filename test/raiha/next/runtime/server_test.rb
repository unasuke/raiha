require "raiha/next/test_helper"
require "raiha/next/support/runtime_owner"
require "async"

# The server of the runtime against clients of the runtime on the loopback
# interface: a Session for the block in a fiber of each connection, the
# connection closed when the block is over or raises, and no more
# connections than it takes at a time.
class RaihaNextRuntimeServerTest < Minitest::Test
  include NextRuntimeOwner

  def connect(port, **options, &)
    tls = client_config
    Runtime::Client.connect("127.0.0.1", port, config: QUIC::Config.new, tls_config: tls, keyring: client_keyring(config: tls),
      server_name: "localhost", **options, &)
  end

  # What a stream of `session` answers to `data`.
  def echo(session, data)
    stream = session.open_stream
    stream << data
    stream.close_write
    stream.read
  end

  def echoes(session) = session.each_stream { |stream| (stream << "ECHO:" << stream.read).close_write }

  # A server of the runtime on a free port running `handler` for each
  # session, for the block, which is given the port, the server and the
  # fiber that runs it; stopped after.
  def serving(handler, max_connections: Runtime::Server::MAX_CONNECTIONS, tls: server_config)
    server = Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1",
      port: 0, max_connections:)
    running = Fiber.schedule { server.run(&handler) }
    sleep 0.01 until server.local_address
    yield server.local_address.fetch(1), server, running
  ensure
    server&.stop(timeout: 1)
    sleep 0.01 while running&.alive?
  end

  def test_each_session_in_a_fiber_of_its_own
    Sync do
      serving(method(:echoes)) do |port|
        replies = {}
        clients = Array.new(3) { |i| Fiber.schedule { replies[i] = connect(port) { |session| echo(session, i.to_s) } } }
        sleep 0.01 while clients.any?(&:alive?)
        assert_equal({ 0 => "ECHO:0", 1 => "ECHO:1", 2 => "ECHO:2" }, replies)
      end
    end
  end

  # The block is over: what it sent comes whole, and the connection closes
  # with the application's error 0.
  def test_a_block_that_returns_closes_its_connection
    Sync do
      serving(->(session) { (session.open_stream(direction: :uni) << "bye").close_write }) do |port|
        connect(port) do |session|
          assert_equal "bye", session.accept_stream.read
          sleep 0.01 until session.closed?
          assert_equal [0, true], session.connection.close_reason.then { [_1.code, _1.application] }
        end
      end
    end
  end

  # The block raises: its connection closes with INTERNAL_ERROR, and the
  # server goes on serving.
  def test_a_block_that_raises_closes_only_its_connection
    level = Console.logger.level
    Console.logger.off!
    Sync do
      calls = 0
      serving(->(session) { (calls += 1) == 1 ? raise("a block that fails") : echoes(session) }) do |port|
        connect(port) do |session|
          sleep 0.01 until session.closed?
          assert_equal [QUIC::ErrorCode::INTERNAL_ERROR, false], session.connection.close_reason.then { [_1.code, _1.application] }
        end
        assert_equal "ECHO:again", connect(port) { |session| echo(session, "again") }
      end
    end
  ensure
    Console.logger.level = level
  end

  def test_no_more_connections_than_it_takes
    Sync do
      serving(method(:echoes), max_connections: 1) do |port|
        connect(port) do |first|
          error = assert_raises(Runtime::ConnectError) { connect(port) { flunk } }
          assert_equal [QUIC::ErrorCode::CONNECTION_REFUSED], error.errors.map { |_, closed| closed.error.code }
          assert_equal "ECHO:still", echo(first, "still")
        end
      end
    end
  end

  # Half the connections taken, a client shows its address with a Retry
  # before it is taken; before then, none is sent.
  def test_a_retry_once_half_the_connections_are_taken
    Sync do
      serving(method(:echoes), max_connections: 2) do |port|
        connect(port) do |first|
          assert_nil first.connection.instance_variable_get(:@retry_source_connection_id)
          connect(port) do |second|
            refute_nil second.connection.instance_variable_get(:@retry_source_connection_id)
            assert_equal "ECHO:second", echo(second, "second")
          end
        end
      end
    end
  end

  # The connections to come take the TLS settings the server is given;
  # one already taken keeps its own.
  def test_reconfigure_for_the_connections_to_come
    Sync do
      serving(method(:echoes)) do |port, server|
        connect(port) do |first|
          other = NextTLSPair.server_config(profile: TLS::Profile::QUIC, alpn: ["h3"], registry: REGISTRY)
          server.reconfigure(tls_config: other, keyring: server_keyring(config: other))
          error = assert_raises(Runtime::ConnectError) { connect(port) { flunk } }
          assert_equal [QUIC::ErrorCode.crypto_error(TLS::IANA.alert_code(:no_application_protocol))],
            error.errors.map { |_, closed| closed.error.code }
          assert_equal "ECHO:still", echo(first, "still")
        end
      end
    end
  end

  # Keys of a ratchet of one-second epochs: once the first is over, the
  # server builds them again for the next connection, which resumes a
  # ticket of the epoch before.
  def test_ratchet_keys_advance
    Sync do
      origin = Time.now
      keys = TLS::TicketKeys.ratchet(base: "\x1e".b * 32, base_epoch: -100, origin:, now: origin, epoch: 1)
      tls = server_config(ticket_keys: keys, ticket_lifetime: 10)
      serving(method(:echoes), tls:) do |port, server|
        ticket = connect(port) do |session|
          session.wait_for(deadline: Runtime::Driver.clock + 2) { session.tickets.first }
          session.tickets.last
        end
        assert_same tls, server.instance_variable_get(:@tls_config)
        sleep 0.01 until Time.now >= origin + 1
        assert connect(port, session: ticket) { |session| session.handshake&.resumed }
        advanced = server.instance_variable_get(:@tls_config)
        assert_equal tls.ticket_keys.next_advance_at + 1, advanced.ticket_keys.next_advance_at
        assert_same advanced, server.instance_variable_get(:@keyring).config
      end
    end
  end

  # A server asked to stop takes no new connection, tells each session it
  # is stopping, and returns from `run` once the sessions have ended their
  # connections.
  def test_stop_lets_the_sessions_end
    begun = false
    handler = lambda do |session|
      begun = true
      sleep 0.01 until session.stopping?
      stream = session.accept_stream
      (stream << "bye after " << stream.read).close_write
    end
    Sync do
      serving(handler) do |port, server, running|
        connect(port) do |session|
          sleep 0.01 until begun
          server.stop(timeout: 5)
          error = assert_raises(Runtime::ConnectError) { connect(port) { flunk } }
          assert_equal [QUIC::ErrorCode::CONNECTION_REFUSED], error.errors.map { |_, closed| closed.error.code }
          assert_equal "bye after stop", echo(session, "stop")
          sleep 0.01 until session.closed?
          assert_equal [0, true], session.connection.close_reason.then { [_1.code, _1.application] }
        end
        started = Runtime::Driver.clock
        sleep 0.01 while running.alive?
        assert_operator Runtime::Driver.clock - started, :<, 2
      end
    end
  end

  # A session waiting for the next stream ends when the server stops, well
  # before the timeout.
  def test_stop_ends_each_stream
    Sync do
      serving(method(:echoes)) do |port, server, running|
        connect(port) do |session|
          assert_equal "ECHO:once", echo(session, "once")
          started = Runtime::Driver.clock
          server.stop(timeout: 5)
          sleep 0.01 until session.closed?
          assert_operator Runtime::Driver.clock - started, :<, 2
          assert_equal [0, true], session.connection.close_reason.then { [_1.code, _1.application] }
        end
        sleep 0.01 while running.alive?
      end
    end
  end

  # What a session has not ended by the timeout closes with the error code
  # `stop` was given.
  def test_stop_closes_what_is_left_at_the_timeout
    begun = false
    handler = lambda do |session|
      begun = true
      sleep 0.01 until session.closed?
    end
    Sync do
      serving(handler) do |port, server, running|
        connect(port) do |session|
          sleep 0.01 until begun
          server.stop(timeout: 0.2, error_code: 7)
          sleep 0.01 until session.closed?
          assert_equal [7, true], session.connection.close_reason.then { [_1.code, _1.application] }
        end
        sleep 0.01 while running.alive?
      end
    end
  end

  # A signal handler may ask a server to stop.
  def test_stop_from_a_signal_handler
    Sync do
      serving(method(:echoes)) do |_port, server, running|
        previous = Signal.trap(:USR2) { server.stop(timeout: 1) }
        Process.kill(:USR2, Process.pid)
        started = Runtime::Driver.clock
        sleep 0.01 while running.alive? && Runtime::Driver.clock - started < 3
        refute running.alive?
      ensure
        Signal.trap(:USR2, previous || "DEFAULT")
      end
    end
  end

  # The task running a server stopped from outside leaves no fiber behind
  # and the socket closed.
  def test_a_run_stopped_from_outside
    Sync do |task|
      tls = server_config
      server = Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1",
        port: 0)
      running = task.async { server.run { flunk } }
      sleep 0.01 until server.local_address
      running.stop
      sleep 0.01 until running.stopped?
      assert server.instance_variable_get(:@udp).closed?
      assert server.instance_variable_get(:@driver).stopped?
    end
  end

  # A stop as `run` closes the pipe raises nothing out of a signal handler,
  # its end read from closed first.
  def test_a_stop_as_the_pipe_closes
    tls = server_config
    server = Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1", port: 0)
    reader, writer = IO.pipe
    reader.close
    server.instance_variable_set(:@wake, writer)
    assert_nil server.stop
  ensure
    writer&.close
  end

  def test_a_scheduler_is_needed
    tls = server_config
    server = Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1", port: 0)
    assert_raises(Runtime::Error::Usage) { server.run { flunk } }
  end
end
