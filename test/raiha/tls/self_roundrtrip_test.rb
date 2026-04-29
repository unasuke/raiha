require "test_helper"
require "support/test_certificate"
require "tmpdir"
require "raiha/tls/client"
require "raiha/tls/server"

class RaihaTLSRoundtripTest < Minitest::Test
  include TestCertificate

  def test_roundtrip1
    client = Raiha::TLS::Client.new
    server = Raiha::TLS::Server.new(config: create_server_config)

    client_first_request = client.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::WAIT_SH, client.state

    server.receive(client_first_request.join)
    assert_equal Raiha::TLS::Server::State::RECVD_CH, server.state

    server_first_response = server.datagrams_to_send
    assert server_first_response

    client.receive(server_first_response.join)
    assert_equal Raiha::TLS::Client::State::WAIT_SEND_FINISHED, client.state

    client_second_request = client.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::CONNECTED, client.state
    assert client.finished?

    server.receive(client_second_request.join)
    assert_equal Raiha::TLS::Server::State::CONNECTED, server.state
    assert server.connected?
  end

  def test_sslkeylogfile_env_var_writes_traffic_secrets
    Dir.mktmpdir do |dir|
      keylog = File.join(dir, "ssl.keylog")
      original = ENV["SSLKEYLOGFILE"]
      ENV["SSLKEYLOGFILE"] = keylog

      begin
        client = Raiha::TLS::Client.new
        server = Raiha::TLS::Server.new(config: create_server_config)

        server.receive(client.datagrams_to_send.join)
        client.receive(server.datagrams_to_send.join)
        server.receive(client.datagrams_to_send.join)
      ensure
        ENV["SSLKEYLOGFILE"] = original
      end

      content = File.read(keylog)
      # Both endpoints write on handshake completion.
      %w[
        SERVER_HANDSHAKE_TRAFFIC_SECRET
        SERVER_TRAFFIC_SECRET_0
        CLIENT_HANDSHAKE_TRAFFIC_SECRET
        CLIENT_TRAFFIC_SECRET_0
      ].each do |label|
        assert_includes content, label
      end
    end
  end

  def test_sslkeylogfile_unset_does_not_create_file
    original = ENV["SSLKEYLOGFILE"]
    ENV.delete("SSLKEYLOGFILE")

    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        client = Raiha::TLS::Client.new
        server = Raiha::TLS::Server.new(config: create_server_config)
        server.receive(client.datagrams_to_send.join)
        client.receive(server.datagrams_to_send.join)
        server.receive(client.datagrams_to_send.join)

        # The legacy hardcoded "SSLKEYLOGFILE" filename must not appear.
        refute File.exist?("SSLKEYLOGFILE")
      end
    end
  ensure
    ENV["SSLKEYLOGFILE"] = original if original
  end
end
