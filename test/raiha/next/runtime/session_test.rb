require "raiha/next/test_helper"
require "raiha/next/support/runtime_owner"
require "async"

# A Session of the runtime between a client and a server on the loopback
# interface: streams read and written as an IO would be, waiting on the
# peer's flow control and stream limits, and what the peer resets, stops or
# closes raised where the application waits.
class RaihaNextRuntimeSessionTest < Minitest::Test
  include NextRuntimeOwner

  # A client's Session and the server's Owner, connected, for the block.
  def connected(server: QUIC::Config.new, client: QUIC::Config.new, server_tls: server_config)
    Sync do
      server_owner = server_owner(server, tls: server_tls)
      endpoint, client_owner = owner(:client, client)
      tls = client_config
      client_owner.add(endpoint.connect(tls_config: tls, keyring: client_keyring(config: tls), server_name: "localhost",
        remote: ["127.0.0.1", server_owner.port], now: Runtime::Driver.clock))
      client_owner.driver.start
      yield client_owner.sessions.first, server_owner
    ensure
      client_owner&.driver&.stop
      server_owner&.driver&.stop
    end
  end

  # Holds the reads of the server back to 16 KiB, so a write of a megabyte
  # waits for room again and again.
  def test_an_echo_held_back_by_flow_control
    payload = Random.new(1).bytes(1_000_000)
    connected(server: QUIC::Config.new(initial_max_stream_data_bidi_remote: 16_384, initial_max_data: 65_536)) do |client, server_owner|
      Fiber.schedule do
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
  # driver goes round only as datagrams and timers come, not for each look
  # the waiting write takes.
  def test_a_write_held_back_does_not_spin
    connected(server: QUIC::Config.new(initial_max_stream_data_bidi_remote: 1_000)) do |client, _server_owner|
      stream = client.open_stream
      Fiber.schedule { stream.write("x" * 100_000) }
      driver = client.instance_variable_get(:@driver)
      owner = driver.instance_variable_get(:@owner)
      sleep 0.1
      before = owner.turns
      sleep 0.3
      assert_operator owner.turns - before, :<, 30
    end
  end

  def test_a_stream_the_peer_resets
    connected do |client, server_owner|
      stream = client.open_stream
      stream.write("hello")
      server = accepted(server_owner)
      Fiber.schedule do
        server.accept_stream.write("partial")
        server.connection.stream_reset(stream.id, error_code: 7)
        server_owner.driver.changed
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
      server_owner.driver.changed
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
      Fiber.schedule { opened = client.open_stream }
      sleep 0.05
      assert_nil opened
      first.close_write
      Fiber.schedule do
        stream = accepted(server_owner).accept_stream
        stream.read
        stream.close_write
      end
      assert_equal "", first.read
      sleep 0.01 until opened
      assert_equal 4, opened.id
    end
  end

  # A stream the peer opens opens those of its type below it, which come
  # first.
  def test_a_stream_opens_those_below_it
    connected do |client, server_owner|
      streams = Array.new(3) { client.open_stream }
      streams.last.write("third")
      server = accepted(server_owner)
      assert_equal [0, 4, 8], Array.new(3) { server.accept_stream.id }
    end
  end

  # Streams opened and ended one after another leave nothing behind at
  # either end, however many there were.
  def test_streams_over_are_forgotten
    connected do |client, server_owner|
      Fiber.schedule do
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
      sleep 0.01 until server.instance_variable_get(:@tracks).empty?
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
      reading = Fiber.schedule do
        assert_raises(RuntimeError, "a turn that fails") { server.accept_stream.read }
      end
      server_owner.driver.send(:fail, RuntimeError.new("a turn that fails"))
      sleep 0.01 while reading.alive?
      client_owner_driver = client.instance_variable_get(:@driver)
      Fiber.schedule { client_owner_driver.stop }
      error = assert_raises(Raiha::Next::QUIC::ClosedError) { stream.read }
      assert_equal "the runtime stopped", error.error.reason
      assert client.closed?
    end
  end

  # What came before the peer closed is still read: a stream that arrived
  # is still accepted, and its data still comes before its end.
  def test_what_came_before_the_close
    connected do |client, server_owner|
      client.open_stream.write("hello")
      server = accepted(server_owner)
      Fiber.schedule do
        (server.open_stream(direction: :uni) << "last words").close_write
        server.wait_acknowledged(1)
        server.close(error_code: 5)
      end
      sleep 0.01 until client.closed?
      stream = client.accept_stream
      assert_equal ["last words", nil], [stream.read(100), stream.read(100)]
      assert_nil client.accept_stream
    end
  end

  # Streams going one way that the peer resets before they are taken leave
  # nothing behind, however many the peer opens.
  def test_reset_streams_not_taken_are_forgotten
    connected do |client, server_owner|
      client.open_stream.write("hello")
      server = accepted(server_owner)
      done = false
      Fiber.schedule do
        300.times do
          stream_id = server.open_stream_id(direction: :uni)
          server.connection.stream_write(stream_id, "x")
          server.connection.stream_reset(stream_id, error_code: 1)
          server.changed
        end
        done = true
      end
      sleep 0.01 until done
      sleep 0.1
      assert_equal [{}, []], [client.instance_variable_get(:@tracks).reject { |id, _| id == 0 }, client.instance_variable_get(:@incoming)]
    end
  end

  # What waits when the peer closes raises the error it closed with, and
  # what comes after does too; the server's streams stop coming.
  def test_the_peer_closes
    connected do |client, server_owner|
      stream = client.open_stream
      stream.write("hello")
      server = accepted(server_owner)
      Fiber.schedule { server.close(error_code: 42, reason: "bye") }
      error = assert_raises(Raiha::Next::QUIC::ClosedError) { stream.read }
      assert_equal [42, true, "bye"], [error.error.code, error.error.application, error.error.reason]
      assert_raises(Raiha::Next::QUIC::ClosedError) { client.open_stream }
      assert client.closed?
      assert_nil server.accept_stream
    end
  end

  # The tickets and the token the server gives once the handshake is over
  # are kept, for later connections.
  def test_tickets_and_tokens
    connected(server_tls: server_config(ticket_key: "\x1c".b * 32)) do |client, _server_owner|
      client.wait_for(deadline: Runtime::Driver.clock + 2) { client.tokens.first && client.tickets[1] }
      assert_equal [QUIC::Session, QUIC::Session], client.tickets.map(&:class)
      assert_equal 1, client.tokens.size
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
    count = Runtime::Session::MAX_HELD + 2
    sessions = Array.new(count) { QUIC::Session.new(tls: nil, transport_parameters: nil, alpn: nil, version: _1) }
    tokens = Array.new(count) { "token#{_1}" }
    events = sessions.map { QUIC::Event::SessionTicket.new(session: _1) } + tokens.map { QUIC::Event::NewToken.new(token: _1) }
    tracer = Recorder.new
    session = Runtime::Session.new(Events.new(events), nil, role: :client, tracer:)
    session.turn
    assert_equal sessions.last(Runtime::Session::MAX_HELD), session.tickets
    assert_equal tokens.last(Runtime::Session::MAX_HELD), session.tokens
    assert_equal [TLS::Trace::TicketIgnored.new(reason: :too_many_tickets)] * 2, tracer.values
  end
end
