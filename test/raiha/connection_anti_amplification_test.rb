require "test_helper"
require "raiha/connection"

class RaihaConnectionAntiAmplificationTest < Minitest::Test
  # RFC 9000 §8.1: before the server has validated the client's address,
  # it MUST NOT send more than 3 times as many bytes as it has received.

  def test_server_blocks_send_exceeding_three_times_received
    server = create_server_connection
    queue_crypto_data(server, "x".b * 100)

    # No bytes received yet → budget = 0, so nothing can go out.
    assert_empty server.get_packets_to_send
  end

  def test_server_sends_within_budget
    server = create_server_connection
    # Simulate a 1200-byte Initial datagram arriving from the client.
    inflate_received(server, 1200)
    queue_crypto_data(server, "x".b * 100)

    packets = server.get_packets_to_send
    refute_empty packets
    total = packets.sum(&:bytesize)
    assert_operator total, :<=, 1200 * 3, "server sent #{total} bytes with budget #{1200 * 3}"
  end

  def test_server_bytes_sent_counter_advances
    server = create_server_connection
    inflate_received(server, 1200)
    queue_crypto_data(server, "x".b * 100)

    server.get_packets_to_send
    assert_operator server.instance_variable_get(:@bytes_sent_to_peer), :>, 0
  end

  def test_complete_handshake_lifts_the_limit
    server = create_server_connection
    server.complete_handshake
    assert server.instance_variable_get(:@address_validated)

    queue_crypto_data(server, "x".b * 100)
    packets = server.get_packets_to_send
    # No received bytes, but validated → send is allowed.
    refute_empty packets
  end

  def test_client_is_never_limited
    # RFC 9000 §8.1 is a server-only MUST; a client with no received
    # bytes yet must still be able to send its first flight.
    client = create_client_connection
    queue_crypto_data(client, "x".b * 100, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    packets = client.get_packets_to_send
    refute_empty packets
  end

  private def create_server_connection
    create_connection(:server)
  end

  private def create_client_connection
    create_connection(:client)
  end

  private def create_connection(perspective)
    Raiha::Connection.new(
      perspective: perspective,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate
    )
  end

  # Feed bytes into the received counter without needing a real datagram.
  private def inflate_received(connection, bytes)
    current = connection.instance_variable_get(:@bytes_received_from_peer)
    connection.instance_variable_set(:@bytes_received_from_peer, current + bytes)
  end

  private def queue_crypto_data(connection, data, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    connection.instance_variable_get(:@crypto_setup).queue_crypto_data(data, level: level)
  end
end
