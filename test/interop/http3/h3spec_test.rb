require "test_helper"
require "support/http3_udp"

# A server of raiha over UDP against h3spec
# (kazu-yamamoto/h3spec, the release `rake interop:build:h3spec` fetches
# into tmp/h3spec), which opens a connection for each of its cases and
# sends what QUIC and HTTP/3 must refuse, checking that the server does.
# Every case passes.
class HTTP3H3specTest < Minitest::Test
  include HTTP3UDP

  H3SPEC = File.expand_path("../../../tmp/h3spec/h3spec", __dir__)

  def setup
    skip "h3spec not found" unless File.executable?(H3SPEC)
  end

  def test_every_case_of_h3spec
    server(alpn: ALPN) do |socket, quic|
      app = Server.new(quic, body: "raiha".b)
      peer(H3SPEC, "--no-validate", "127.0.0.1", socket.addr[1].to_s) do |output|
        done = drive(socket, quic, seconds: 300) do
          app.step(mono)
          plain(output).match?(/^\d+ examples?, \d+ failures?/)
        end
        assert done, output
        assert_match(/^\d+ examples?, 0 failures/, plain(output), output)
      end
    end
  end

  # h3spec colours its summary on GitHub Actions, where it takes stdout for
  # a terminal.
  private def plain(output) = output.gsub(/\e\[[\d;]*m/, "")
end
