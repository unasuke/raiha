require "test_helper"
require "support/http3_udp"
require "fileutils"

# A client of the next release of raiha over UDP against quiche's HTTP/3
# server (quiche-server of tmp/quiche), which serves the files of a
# directory with a certificate of the test CA, sends a Retry first and
# sends GREASE. The client asks for two files at once.
class NextHTTP3QuicheServerTest < Minitest::Test
  include NextHTTP3UDP

  SERVER = File.expand_path("../../../tmp/quiche/target/release/quiche-server", __dir__)
  FILES = { "/index.html" => "<p>raiha</p>\n".b, "/large" => Random.new(1).bytes(500_000) }.freeze

  def setup
    skip "quiche-server not found" unless File.executable?(SERVER)
    @dir = Dir.mktmpdir("next-interop-quiche-server-", TMP)
    @root = File.join(@dir, "root").tap { Dir.mkdir(_1) }
    FILES.each { |path, body| File.binwrite(File.join(@root, path), body) }
  end

  def teardown
    FileUtils.rm_rf(@dir) if @dir
  end

  def test_requests_to_quiche_server
    port = free_port
    chain, key = certificate_files(@dir)
    peer({ "RUST_LOG" => "info" }, SERVER, "--listen", "127.0.0.1:#{port}", "--cert", chain, "--key", key, "--root", @root) do |output|
      assert wait_for(output, "listening on"), output
      client(port, alpn: ALPN) do |socket, connection|
        app = Client.new(connection, authority: "localhost:#{port}", paths: FILES.keys)
        assert drive(socket, connection, seconds: 20) { app.step(mono) || connection.closed? }, output
        assert_equal FILES.transform_values { ["200", _1] }, app.responses, "#{connection.close_reason.inspect}\n#{output}"
      end
    end
  end
end
