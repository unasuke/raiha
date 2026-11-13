require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# A server Connection taking the client's NEW_CONNECTION_ID frames: it
# sends to the ID in use, retires what Retire Prior To asks, and takes no
# RETIRE_CONNECTION_ID, having issued no ID to retire.
class RaihaNextQUICConnectionConnectionIDsTest < Minitest::Test
  include NextQUICPair

  def setup
    @keylog = Keylog.new
    @client = client_connection(keylog: @keylog)
    @server = server_connection
    first = @client.transmits(now: 0.0).first.payload
    @client_id = QUIC::Wire::Packet.parse(first, dcid_length: 8).header.scid
    @server.receive(first, from: CLIENT, now: 0.0)
    reply = @server.transmits(now: 0.0)
    @server_id = QUIC::Wire::Packet.parse(reply.first.payload, dcid_length: 8).header.scid
    reply.each { @client.receive(_1.payload, from: SERVER, now: 0.0) }
    handshake(@client, @server)
    @number = 1000
  end

  def send_frames(*frames, now: 0.1)
    payload = QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3)
    @server.receive(client_one_rtt(@keylog, dcid: @server_id, payload:, packet_number: @number += 1), from: CLIENT, now:)
  end

  # The server's 1-RTT datagrams now: the Destination Connection ID of
  # each, and their frames.
  def server_packets(now: 0.2)
    @server.transmits(now:).filter_map do |transmit|
      dcid = QUIC::Wire::Packet.parse(transmit.payload, dcid_length: 8).header.dcid
      opened = server_one_rtt(@keylog, transmit.payload, phase: 0) or next
      [dcid, opened.last]
    end
  end

  # Retire Prior To 1 retires the client's first ID: the server sends to the
  # new one from then on, and RETIRE_CONNECTION_ID(0) back.
  def test_the_id_in_use_retired
    fresh = "n".b * 8
    send_frames(QUIC::Wire::Frame::NewConnectionID.new(sequence_number: 1, retire_prior_to: 1, connection_id: fresh,
      stateless_reset_token: "r".b * 16))
    packets = server_packets
    refute_empty packets
    assert packets.all? { |dcid, _| dcid == fresh }
    assert_includes packets.flat_map(&:last), QUIC::Wire::Frame::RetireConnectionID.new(sequence_number: 0)
    refute_equal @client_id, fresh
  end

  def test_no_id_to_retire
    send_frames(QUIC::Wire::Frame::RetireConnectionID.new(sequence_number: 0))
    assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, @server.close_reason&.code
  end

  # More IDs than the server's active_connection_id_limit, 8.
  def test_over_the_limit
    frames = (1..8).map do |sequence_number|
      QUIC::Wire::Frame::NewConnectionID.new(sequence_number:, retire_prior_to: 0, connection_id: [sequence_number].pack("C") * 8,
        stateless_reset_token: [sequence_number].pack("C") * 16)
    end
    send_frames(*frames)
    assert_equal QUIC::ErrorCode::CONNECTION_ID_LIMIT_ERROR, @server.close_reason&.code
  end
end
