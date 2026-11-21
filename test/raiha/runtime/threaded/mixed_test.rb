require "test_helper"
require "support/threaded_owner"
require "async"

# The runtime on threads and the runtime of fibers at the two ends of one
# connection: each speaks QUIC to the other, whichever serves. Apart from
# the other tests of threads, as these need a Fiber scheduler.
class RaihaRuntimeThreadedMixedTest < Minitest::Test
  include ThreadedOwner

  def options
    tls = client_config
    { config: QUIC::Config.new, tls_config: tls, keyring: client_keyring(config: tls), server_name: "localhost" }
  end

  def echoes(session) = session.each_stream { |stream| (stream << "ECHO:" << stream.read).close_write }

  def echo(session, data)
    stream = session.open_stream
    (stream << data).close_write
    stream.read
  end

  def test_a_server_on_threads_and_a_client_of_fibers
    tls = server_config
    server = Threaded::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1", port: 0)
    running = Thread.new { server.run { |session| echoes(session) } }
    sleep 0.01 until server.local_address
    echoed = Sync { Runtime::Client.connect("127.0.0.1", server.local_address.fetch(1), **options) { |session| echo(session, "fibers") } }
    assert_equal "ECHO:fibers", echoed
  ensure
    server&.stop(timeout: 1)
    running&.join(10)
  end

  def test_a_server_of_fibers_and_a_client_on_threads
    Sync do
      tls = server_config
      server = Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls), host: "127.0.0.1", port: 0)
      running = Fiber.schedule { server.run { |session| echoes(session) } }
      sleep 0.01 until server.local_address
      port = server.local_address.fetch(1)
      echoed = Thread.new { Threaded::Client.connect("127.0.0.1", port, **options) { |session| echo(session, "threads") } }.value
      assert_equal "ECHO:threads", echoed
    ensure
      server&.stop(timeout: 1)
      sleep 0.01 while running&.alive?
    end
  end
end
