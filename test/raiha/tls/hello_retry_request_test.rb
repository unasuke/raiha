require "test_helper"
require "raiha/tls/client"
require "raiha/tls/server"

class RaihaTLSHelloRetryRequestTest < Minitest::Test
  # Scenario: Client advertises x25519 in supported_groups but only
  # sends prime256v1 key_share. Server prefers x25519, finds no matching
  # key_share, and sends HelloRetryRequest. Client rebuilds ClientHello
  # with x25519 key_share and handshake completes.
  def test_hello_retry_request_roundtrip
    client = Raiha::TLS::Client.new
    server = Raiha::TLS::Server.new

    # Intercept: build ClientHello but patch supported_groups to include x25519
    # so server selects x25519 but key_share only has prime256v1 → HRR
    client_hello_records = client.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::WAIT_SH, client.state

    # Patch the supported_groups in the serialized ClientHello to add x25519
    # Instead, we'll use a different approach: manually set server to prefer
    # a group that client doesn't have in key_share

    # Actually, let's modify the approach: override the client's extensions
    # We need a fresh client where supported_groups includes x25519 but
    # key_share only has prime256v1

    # Reset and use a subclass approach for testing
    client2 = TestClientWithLimitedKeyShare.new
    server2 = Raiha::TLS::Server.new

    # 1. Client sends ClientHello (supported_groups: [x25519, prime256v1], key_share: [prime256v1])
    client_hello_records = client2.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::WAIT_SH, client2.state

    # 2. Server receives, picks x25519, no key_share → HRR
    server2.receive(client_hello_records.join)
    assert_equal Raiha::TLS::Server::State::RECVD_CH, server2.state

    hrr_response = server2.datagrams_to_send
    assert_equal Raiha::TLS::Server::State::WAIT_CH_RETRY, server2.state

    # 3. Client receives HRR
    client2.receive(hrr_response.join)
    assert_equal Raiha::TLS::Client::State::WAIT_SH_RETRY, client2.state

    # 4. Client sends retry ClientHello with x25519
    retry_records = client2.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::WAIT_SH, client2.state

    # 5. Server processes retry → full handshake
    server2.receive(retry_records.join)
    server_flight = server2.datagrams_to_send

    # 6. Client processes server flight
    client2.receive(server_flight.join)
    assert_equal Raiha::TLS::Client::State::WAIT_SEND_FINISHED, client2.state

    # 7. Client sends Finished
    client_finished = client2.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::CONNECTED, client2.state

    # 8. Server receives Finished
    server2.receive(client_finished.join)
    assert_equal Raiha::TLS::Server::State::CONNECTED, server2.state
  end

  # Test client that advertises x25519 in supported_groups but only
  # generates prime256v1 key_share, forcing HelloRetryRequest
  class TestClientWithLimitedKeyShare < Raiha::TLS::Client
    def initialize
      super(config: Raiha::TLS::Config.new(
        cipher_suites: Raiha::TLS::Config::DEFAULT_CIPHER_SUITES,
        supported_groups: ["prime256v1"] # key_share will only have prime256v1
      ))
    end

    # Override build_client_hello to add x25519 to supported_groups extension
    # while keeping key_share as prime256v1 only
    def build_client_hello
      result = super
      # Patch: add x25519 to the supported_groups extension in @client_hello
      sg_ext = @client_hello.extensions.find { |e| e.is_a?(Raiha::TLS::Handshake::Extension::SupportedGroups) }
      sg_ext.groups = ["x25519", "prime256v1"] if sg_ext

      # Re-serialize with patched extensions
      hs = Raiha::TLS::Handshake.new
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = @client_hello
      @transcript_hash[:client_hello] = hs.serialize
      Raiha::TLS::Record::TLSPlaintext.serialize(hs)
    end
  end
end
