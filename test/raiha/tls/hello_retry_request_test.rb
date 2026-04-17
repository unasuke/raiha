require "test_helper"
require "support/test_certificate"
require "raiha/tls/client"
require "raiha/tls/server"

class RaihaTLSHelloRetryRequestTest < Minitest::Test
  include TestCertificate

  def test_hello_retry_request_roundtrip
    client = TestClientWithLimitedKeyShare.new
    server = Raiha::TLS::Server.new(config: create_server_config)

    # 1. Client sends ClientHello (supported_groups: [x25519, prime256v1], key_share: [prime256v1])
    client_hello_records = client.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::WAIT_SH, client.state

    # 2. Server receives, picks x25519, no key_share → HRR
    server.receive(client_hello_records.join)
    assert_equal Raiha::TLS::Server::State::RECVD_CH, server.state

    hrr_response = server.datagrams_to_send
    assert_equal Raiha::TLS::Server::State::WAIT_CH_RETRY, server.state

    # 3. Client receives HRR
    client.receive(hrr_response.join)
    assert_equal Raiha::TLS::Client::State::WAIT_SH_RETRY, client.state

    # 4. Client sends retry ClientHello with x25519
    retry_records = client.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::WAIT_SH, client.state

    # 5. Server processes retry → full handshake
    server.receive(retry_records.join)
    server_flight = server.datagrams_to_send

    # 6. Client processes server flight
    client.receive(server_flight.join)
    assert_equal Raiha::TLS::Client::State::WAIT_SEND_FINISHED, client.state

    # 7. Client sends Finished
    client_finished = client.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::CONNECTED, client.state

    # 8. Server receives Finished
    server.receive(client_finished.join)
    assert_equal Raiha::TLS::Server::State::CONNECTED, server.state
  end

  class TestClientWithLimitedKeyShare < Raiha::TLS::Client
    def initialize
      super(config: Raiha::TLS::Config.new(
        cipher_suites: Raiha::TLS::Config::DEFAULT_CIPHER_SUITES,
        supported_groups: ["prime256v1"]
      ))
    end

    def build_client_hello
      super
      sg_ext = @client_hello.extensions.find { |e| e.is_a?(Raiha::TLS::Handshake::Extension::SupportedGroups) }
      sg_ext.groups = ["x25519", "prime256v1"] if sg_ext

      hs = Raiha::TLS::Handshake.new
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = @client_hello
      @transcript_hash[:client_hello] = hs.serialize
      Raiha::TLS::Record::TLSPlaintext.serialize(hs)
    end
  end
end
