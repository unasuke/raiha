require "test_helper"
require "support/http3_udp"
require "fileutils"
require "json"

# A server of the next release of raiha over UDP against quiche's HTTP/3
# client (quiche-client of tmp/quiche), which checks the server's
# certificate against the test CA, sends GREASE, and prints the responses
# as JSON. The server answers every request with 200 and BODY.
class HTTP3QuicheClientTest < Minitest::Test
  include HTTP3UDP

  CLIENT = File.expand_path("../../../tmp/quiche/target/release/quiche-client", __dir__)
  BODY = (0...100_000).map { ("a".ord + (_1 % 26)).chr }.join.b.freeze

  def setup
    skip "quiche-client not found" unless File.executable?(CLIENT)
    @dir = Dir.mktmpdir("next-interop-quiche-client-", TMP)
    @ca = File.join(@dir, "ca.pem").tap { File.write(_1, TLSPair.ca.certificate.to_pem) }
  end

  def teardown
    FileUtils.rm_rf(@dir) if @dir
  end

  def test_requests_from_quiche_client
    responses = run_client("-n", "3", "/test")
    assert_equal 3, responses.size
    responses.each do |response|
      assert_includes response["headers"], { "name" => ":status", "value" => "200" }
      assert_equal BODY, response["body"].pack("C*")
    end
  end

  # RFC 9218: quiche-client sends PRIORITY_UPDATE for a URL that asks for
  # an urgency, before the request.
  def test_a_request_with_a_priority_update
    responses = run_client("--send-priority-update", "/test?u=1&i")
    assert_equal [BODY], responses.map { _1["body"].pack("C*") }
  end

  # Runs quiche-client with `arguments`, the last of them a path, against
  # a server until it has printed the responses, and gives them.
  private def run_client(*arguments, path)
    printed = nil
    server(alpn: ALPN) do |socket, quic|
      app = Server.new(quic, body: BODY)
      port = socket.addr[1]
      command = [CLIENT, "--trust-origin-ca-pem", @ca, "--connect-to", "127.0.0.1:#{port}", "--dump-json", "--max-json-payload", BODY.bytesize.to_s,
        *arguments, "https://localhost:#{port}#{path}"]
      peer(*command) do |output|
        assert drive(socket, quic, seconds: 20) {
          app.step(mono)
          printed = responses(output)
        }, output
      end
    end
    printed
  end

  # The responses quiche-client printed in JSON once it was done, each
  # with its headers and its body as bytes; nil before.
  private def responses(output)
    json = output[/^\{\n.*/m] or return nil
    JSON.parse(json).fetch("entries").map { _1.fetch("response") }
  rescue JSON::ParserError
    nil
  end
end
