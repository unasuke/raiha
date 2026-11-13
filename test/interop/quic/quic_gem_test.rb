require "test_helper"
require "support/quic_udp"

# The next release of raiha over UDP against the quic gem (github:
# unasuke/quic-ruby, ngtcp2 and picotls bound to Ruby), which has a client
# only: a server against its client, run as a process of its own as it
# runs its own loop. The client sends data on a stream and prints ECHO_OK
# when what comes back is "ECHO:" and the data. Without data, it would end
# as soon as its own handshake is done, before its Finished goes, so the
# handshake is tried with the echo alone.
class QUICQuicGemInteropTest < Minitest::Test
  include QUICUDP

  CLIENT = File.expand_path("../../support/quic_gem_echo_client.rb", __dir__)
  ALPN = ["raiha-interop"].freeze
  PAYLOAD = Random.new(1).bytes(20_000)

  def setup
    skip "quic gem not installed (run: bundle install --with interop)" unless Gem.loaded_specs.key?("quic")
  end

  # The quic gem's client with `options`, against the server on `socket`.
  def quic_gem_client(socket, *options, &)
    peer("bundle", "exec", "ruby", CLIENT, "--host", "127.0.0.1", "--port", socket.addr[1].to_s, "--alpn", ALPN.first, *options, &)
  end

  def test_echo_to_quic_gem_client
    server(alpn: ALPN) do |socket, server|
      echo = EchoServer.new(server)
      quic_gem_client(socket, "--data", PAYLOAD.unpack1("H*")) do |output|
        done = drive(socket, server, seconds: 30) do
          echo.step
          output.include?("ECHO_OK") || output.include?("ECHO_MISMATCH")
        end
        assert done, output
        assert_includes output, "ECHO_OK"
      end
    end
  end
end
