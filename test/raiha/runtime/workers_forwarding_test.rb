require "test_helper"
require "raiha/runtime"
require "support/runtime_owner"
require "support/quic_udp"
require "async"

# Workers on one port of the loopback interface, with SO_REUSEPORT, and a
# client that keeps moving to sockets of other ports. With two, it lands on
# the other worker sooner or later, which hands its datagrams on to the
# worker of the connection; with one, the server takes each move itself.
# What the client sent comes back whole either way. The client is a bare
# Connection with an issuer of its own, as an Endpoint's would be, so that
# the server has a connection ID to answer a new port with.
class RaihaNextRuntimeWorkersForwardingTest < Minitest::Test
  include NextRuntimeOwner
  include NextQUICUDP

  # How many times the client moves to another port at most: each move
  # lands on the other worker about half of the time.
  MOVES = 32
  PIECE = 1000

  def setup
    skip "SO_REUSEPORT spreads datagrams on Linux alone" unless RUBY_PLATFORM.include?("linux")
  end

  ISSUER = QUIC::Endpoint::Issuer.new(->(_connection) { [SecureRandom.bytes(8), SecureRandom.bytes(16)] }, ->(_connection_id) {})

  # Workers serving echo, each answering with its ID, in a thread of their
  # own.
  def serving(count:)
    tls = server_config
    workers = Runtime::Workers.new(count:, config: QUIC::Config.new, host: "127.0.0.1", port: 0,
      args: [tls, Ractor.make_shareable(NextTLSPair.server_identity)]) do |worker, tls, identity|
      keyring = Raiha::TLS::Keyring.server(config: tls, identities: [identity])
      Sync do
        Raiha::Runtime::Server.new(config: worker.config, tls_config: tls, keyring:, worker:).run do |session|
          session.each_stream { |stream| (stream << "ECHO#{worker.id}:" << stream.read).close_write }
        end
      end
    end
    running = Thread.new { workers.run }
    sleep 0.01 until workers.local_address || !running.alive?
    [workers, running]
  end

  def bound
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    socket
  end

  def forwarded(workers) = workers.stats.sum { |stats| stats&.sent || 0 }

  def test_a_connection_handed_on_between_workers
    workers, running = serving(count: 2)
    socket, sent = moving(workers) { |moves| forwarded(workers).zero? && moves < MOVES }
    assert_operator forwarded(workers), :>, 0, "no datagram was handed on in #{MOVES} moves"
    assert_echoed(socket, sent)
  ensure
    @socket&.close
    workers&.stop(timeout: 1)
    running&.join(10)
  end

  # One worker takes every move of the client itself: the migration of the
  # runtime's server, with nothing handed on.
  def test_a_connection_that_moves_with_one_worker
    workers, running = serving(count: 1)
    socket, sent = moving(workers) { |moves| moves < 3 }
    assert_echoed(socket, sent)
    assert_equal 0, forwarded(workers)
  ensure
    @socket&.close
    workers&.stop(timeout: 1)
    running&.join(10)
  end

  # Connects to `workers` and writes a piece on a stream from a socket of
  # another port each time, while the block is true of the moves so far:
  # the socket it is on last, and what it wrote.
  def moving(workers)
    tls = client_config
    @connection = QUIC::Connection.client(config: QUIC::Config.new, tls_config: tls, keyring: client_keyring(config: tls),
      server_name: "localhost", remote: workers.local_address, time: Time.now, now: mono, issuer: ISSUER)
    connection = @connection
    @socket = bound
    assert drive(@socket, connection) { connection.handshake_confirmed? }
    @stream_id = connection.open_stream
    sent = "".b
    moves = 0
    while yield(moves)
      @socket.close
      @socket = bound
      moves += 1
      piece = SecureRandom.bytes(PIECE)
      assert_equal PIECE, connection.stream_write(@stream_id, piece)
      sent << piece
      drive(@socket, connection, seconds: 0.2) { false }
    end
    [@socket, sent]
  end

  # Ends the stream and waits for the echo of `sent`.
  def assert_echoed(socket, sent)
    connection = @connection
    stream_id = @stream_id
    connection.stream_write(stream_id, "".b, fin: true)
    received = "".b
    ended = drive(socket, connection) do
      while (chunk = connection.stream_read(stream_id, 65_536))
        break if chunk.empty?
        received << chunk
      end
      chunk.nil?
    end
    assert ended, "the echo did not end"
    assert_match(/\AECHO[01]:/, received)
    assert_equal sent, received.byteslice(6..)
  end
end
