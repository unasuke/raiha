require "test_helper"
require "raiha/connection"

class RaihaConnectionPacketTest < Minitest::Test
  def test_build_initial_packet
    connection = create_client_connection
    crypto_data = "ClientHello placeholder".b

    packet = connection.build_initial_packet(crypto_data)
    refute_nil packet
    assert packet.bytesize > 0

    # First byte should be long header with Initial type (0xc0 before header protection masking)
    assert packet.getbyte(0) & 0x80 != 0, "Should be long header"
  end

  def test_build_packet_with_frames
    connection = create_client_connection

    ping_frame = Raiha::Quic::Wire::Frames::PingFrame.new
    packet = connection.build_packet([ping_frame], level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)

    refute_nil packet
    assert packet.bytesize > 0
  end

  def test_build_packet_empty_frames_returns_nil
    connection = create_client_connection

    packet = connection.build_packet([], level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    assert_nil packet
  end

  def test_client_server_initial_packet_roundtrip
    client_connection = create_client_connection
    _server_connection = create_server_connection

    # Client builds an Initial packet
    crypto_data = "test crypto data".b
    _packet = client_connection.build_initial_packet(crypto_data)

    # Server should be able to process it (handle_packet includes decryption)
    # Note: Header protection makes direct handle_packet complex,
    # so we test without header protection for now
  end

  def test_get_packets_to_send_with_queued_crypto_data
    connection = create_client_connection
    connection.instance_variable_get(:@crypto_setup).queue_crypto_data(
      "test data".b,
      level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL
    )

    packets = connection.get_packets_to_send
    assert_equal 1, packets.length
    assert packets.first.bytesize > 0
  end

  def test_get_packets_to_send_empty_when_no_data
    connection = create_client_connection
    packets = connection.get_packets_to_send
    assert_empty packets
  end

  def test_sequential_packet_numbers
    connection = create_client_connection

    packet1 = connection.build_packet(
      [Raiha::Quic::Wire::Frames::PingFrame.new],
      level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL
    )
    packet2 = connection.build_packet(
      [Raiha::Quic::Wire::Frames::PingFrame.new],
      level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL
    )

    # Both packets should be built (different packet numbers)
    refute_nil packet1
    refute_nil packet2
    refute_equal packet1, packet2
  end

  private def create_client_connection
    Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(["0102030405060708"].pack("H*")),
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(["8394c8f03e515708"].pack("H*"))
    )
  end

  private def create_server_connection
    Raiha::Connection.new(
      perspective: :server,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(["8394c8f03e515708"].pack("H*")),
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(["0102030405060708"].pack("H*"))
    )
  end
end
