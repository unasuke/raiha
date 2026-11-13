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
  def serving(handler, max_connections: Runtime::Server::MAX_CONNECTIONS, tls: server_config, config: QUIC::Config.new, **options)
    server = Runtime::Server.new(config:, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1", port: 0,
      max_connections:, **options)
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

  # A client's first Initial from a socket of its own that sends nothing
  # more: a connection whose address the handshake never validates.
  def silent_client(port)
    tls = client_config
    connection = QUIC::Connection.client(config: QUIC::Config.new, tls_config: tls, keyring: client_keyring(config: tls),
      server_name: "localhost", remote: ["127.0.0.1", port], time: Time.now, now: 0.0)
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    connection.transmits(now: 0.0).each { socket.send(_1.payload, 0, "127.0.0.1", port) }
    socket
  end

  # Once max_unvalidated connections have addresses not validated, a
  # client shows its address with a Retry before it is taken; a connection
  # whose handshake is done, open still, counts for nothing.
  def test_a_retry_once_max_unvalidated_are_not_validated
    Sync do
      serving(method(:echoes), max_unvalidated: 1) do |port|
        connect(port) do |first|
          assert_equal "ECHO:first", echo(first, "first")
          connect(port) do |second|
            assert_nil second.connection.instance_variable_get(:@retry_source_connection_id)
            assert_equal "ECHO:second", echo(second, "second")
          end
          silent = silent_client(port)
          sleep 0.05
          connect(port) do |third|
            refute_nil third.connection.instance_variable_get(:@retry_source_connection_id)
            assert_equal "ECHO:third", echo(third, "third")
          end
        ensure
          silent&.close
        end
      end
    end
  end

  # With max_unvalidated 0, every client shows its address with a Retry.
  def test_a_retry_for_every_client
    Sync do
      serving(method(:echoes), max_unvalidated: 0) do |port|
        connect(port) do |session|
          refute_nil session.connection.instance_variable_get(:@retry_source_connection_id)
          assert_equal "ECHO:retried", echo(session, "retried")
        end
      end
    end
  end

  def test_max_unvalidated_from_0_to_max_connections
    tls = server_config
    [-1, 3, 1.5].each do |max_unvalidated|
      assert_raises(ArgumentError) do
        Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), max_connections: 2,
          max_unvalidated:)
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

  # How a client's 0-RTT on a second connection to a server of `options`
  # that allows it goes.
  def zero_rtt_state(**options)
    Sync do
      serving(method(:echoes), tls: server_config(ticket_key: "\x1f".b * 32, max_early_data_size: 16_384), **options) do |port|
        ticket = connect(port) do |session|
          session.wait_for(deadline: Runtime::Driver.clock + 2) { session.tickets.first }
          session.tickets.last
        end
        connect(port, session: ticket, early_data: true) do |session|
          session.wait_handshake
          session.connection.zero_rtt_state
        end
      end
    end
  end

  # A server given no record of the 0-RTT it takes has one of its own,
  # which takes none for its first seconds, in case it took some before a
  # restart.
  def test_a_record_of_its_own
    assert_equal :rejected, zero_rtt_state
  end

  def test_a_record_given
    assert_equal :accepted, zero_rtt_state(anti_replay: TLS::AntiReplay::Memory.new(now: Time.now, warmup: false))
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

  # A server with a preferred address listens there too: its client moves
  # there once the handshake is confirmed, and the server answers from it.
  def test_a_preferred_address
    Sync do
      preferred = ["127.0.0.1", free_port]
      serving(method(:echoes), config: QUIC::Config.new(preferred_address: { ipv4: preferred })) do |port|
        reply = connect(port) do |session|
          500.times { session.connection.path.remote == preferred ? break : sleep(0.01) }
          [session.connection.path.remote, echo(session, "moved")]
        end
        assert_equal [preferred, "ECHO:moved"], reply
      end
    end
  end

  # Runs the block with no socket binding to "::", as where IPv6 is off.
  def without_ipv6
    bind = Runtime::UDP.method(:bind)
    Runtime::UDP.define_singleton_method(:bind) { |host, port| host == "::" ? raise(Errno::EAFNOSUPPORT) : bind.call(host, port) }
    yield
  ensure
    Runtime::UDP.define_singleton_method(:bind, bind) if bind
  end

  # Skips the test where "::1" cannot be bound.
  def need_ipv6
    socket = UDPSocket.new(Socket::AF_INET6)
    socket.bind("::1", 0)
  rescue SystemCallError
    skip "::1 cannot be bound here"
  ensure
    socket&.close
  end

  # A server on IPv4 that prefers an IPv6 address as well: its client,
  # bound to "::", sends to either, and moves to IPv6.
  def test_a_client_moves_to_ipv6_from_ipv4
    need_ipv6
    Sync do
      preferred = { ipv4: ["127.0.0.1", free_port], ipv6: ["::1", free_port] }
      serving(method(:echoes), config: QUIC::Config.new(preferred_address: preferred)) do |port|
        reply = connect(port) do |session|
          500.times { session.connection.path.remote == preferred[:ipv6] ? break : sleep(0.01) }
          [session.connection.path.remote, echo(session, "moved")]
        end
        assert_equal [preferred[:ipv6], "ECHO:moved"], reply
      end
    end
  end

  # Where IPv6 is off, a client's socket is bound to "0.0.0.0", and it
  # moves to the IPv4 address of the two preferred.
  def test_a_client_where_ipv6_is_off
    need_ipv6
    Sync do
      preferred = { ipv4: ["127.0.0.1", free_port], ipv6: ["::1", free_port] }
      serving(method(:echoes), config: QUIC::Config.new(preferred_address: preferred)) do |port|
        without_ipv6 do
          reply = connect(port) do |session|
            500.times { session.connection.path.remote == preferred[:ipv4] ? break : sleep(0.01) }
            [session.connection.path.remote, echo(session, "moved")]
          end
          assert_equal [preferred[:ipv4], "ECHO:moved"], reply
        end
      end
    end
  end

  # A preferred address the server cannot bind a socket to is never
  # offered: `run` raises.
  def test_a_preferred_address_that_cannot_be_bound
    Sync do
      tls = server_config
      server = Runtime::Server.new(config: QUIC::Config.new(preferred_address: { ipv4: ["192.0.2.1", 4434] }), tls_config: tls,
        keyring: server_keyring(config: tls), host: "127.0.0.1", port: 0)
      assert_raises(Errno::EADDRNOTAVAIL) { server.run { flunk } }
    end
  end

  # A worker of one, on a socket bound here as Workers would bind it.
  def worker
    inbox = Ractor::Port.new
    Runtime::Worker.new(id: 0, count: 1, sockets: [Runtime::UDP.open("127.0.0.1", 0, reuse_port: true)], inbox:,
      control: Ractor::Port.new, peers: [inbox], config: Raiha::Next::QUIC::Config.new(retry_token_key: "r".b * 32, stateless_reset_key: "k".b * 32),
      anti_replay: Raiha::Next::TLS::AntiReplay::Memory.new(now: Time.now))
  end

  # A server given a worker binds nothing, reads the worker's socket,
  # takes a Config without keys, filling them with the worker's, and
  # records 0-RTT in the worker's shared record; a stop
  # asked through the worker's control port ends `run`.
  def test_a_server_of_a_worker
    Sync do
      worker = worker()
      port = worker.sockets.first.local_address.ip_port
      tls = server_config
      server = Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), worker:)
      running = Fiber.schedule { server.run(&method(:echoes)) }
      assert_equal ["127.0.0.1", port], server.local_address
      # 0-RTT is recorded where every worker records it.
      assert_same worker.anti_replay, server.instance_variable_get(:@anti_replay)
      assert_equal "ECHO:hi", connect(port) { |session| echo(session, "hi") }
      worker.control.send([:stop, 1])
      sleep 0.01 while running.alive?
      assert worker.inbox.closed?
    end
  end

  # What fails in the thread that waits on the worker's ports ends `run`
  # with it.
  def test_a_failure_of_the_worker_thread
    Sync do
      worker = worker()
      worker.define_singleton_method(:queue) { |*| raise "the worker thread failed" }
      tls = server_config
      server = Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), worker:)
      failure = nil
      running = Fiber.schedule do
        server.run { flunk }
      rescue RuntimeError => error
        failure = error
      end
      worker.inbox.send(["x".b, ["127.0.0.1", 1], nil, :not_ect, 0.0])
      sleep 0.01 while running.alive?
      assert_equal "the worker thread failed", failure&.message
    end
  end

  def test_a_worker_binds_no_host_or_port
    tls = server_config
    worker = worker()
    assert_raises(ArgumentError) do
      Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), worker:, port: 443)
    end
    assert_raises(ArgumentError) do
      Runtime::HTTP3::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), worker:, host: "::")
    end
  ensure
    worker&.sockets&.each(&:close)
    worker&.close
  end
end
