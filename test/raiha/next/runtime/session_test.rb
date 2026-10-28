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
  def connected(server: QUIC::Config.new, client: QUIC::Config.new)
    Sync do
      server_owner = server_owner(server)
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
end
