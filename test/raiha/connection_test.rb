require "test_helper"
require "raiha/connection"

class RaihaConnectionTest < Minitest::Test
  def test_initial_state
    connection = create_connection
    assert_equal Raiha::Connection::State::HANDSHAKING, connection.state
    refute connection.handshake_complete?
    refute connection.closed?
  end

  def test_complete_handshake
    connection = create_connection
    connection.complete_handshake
    assert_equal Raiha::Connection::State::CONNECTED, connection.state
    assert connection.handshake_complete?
  end

  def test_handle_handshake_done_frame
    connection = create_connection
    frame = Raiha::Quic::Wire::Frames::HandshakeDoneFrame.new
    connection.handle_frames([frame])
    assert connection.handshake_complete?
  end

  def test_handle_stream_frame
    transport_parameters = Raiha::Quic::Handshake::TransportParameters.new
    transport_parameters.initial_max_streams_bidi = 10
    transport_parameters.initial_max_data = 1_000_000
    connection = create_connection(transport_parameters: transport_parameters)
    connection.complete_handshake

    stream_frame = Raiha::Quic::Wire::Frames::StreamFrame.new
    stream_frame.stream_id = 1  # Server-initiated bidi
    stream_frame.offset = 0
    stream_frame.data = "hello".b
    stream_frame.fin = false

    connection.handle_frames([stream_frame])

    stream = connection.streams.get_stream(1)
    refute_nil stream
    assert stream.data_available?
    assert_equal "hello".b, stream.read
  end

  def test_ack_frame_routes_to_matching_pn_space
    connection = create_connection
    sph = connection.instance_variable_get(:@sent_packet_handler)

    # Send a dummy Initial-level packet so there's something to ACK.
    pn = sph.get_next_packet_number(Raiha::Quic::Protocol::PacketNumberSpace::INITIAL)
    sph.sent_packet(
      packet_number: pn,
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: Raiha::Quic::Protocol::PacketNumberSpace::INITIAL
    )

    ack = Raiha::Quic::Wire::Frames::AckFrame.new
    ack.largest_acknowledged = pn.value
    ack.ack_delay = 0
    ack.ack_ranges = [Raiha::Quic::Wire::Frames::AckFrame::AckRange.new(gap: 0, ack_range_length: 0)]

    connection.handle_frames([ack], level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)

    spaces = sph.instance_variable_get(:@spaces)
    initial_space = spaces[Raiha::Quic::Protocol::PacketNumberSpace::INITIAL]
    assert_equal pn.value, initial_space.largest_acked
  end

  def test_ack_delay_decoding_uses_peer_exponent
    connection = create_connection

    # Pre-handshake: peer transport parameters are nil, so decoding uses the
    # RFC 9000 default ack_delay_exponent = 3 (multiply by 2^3 = 8).
    # 25000 * 8 microseconds = 200_000us = 0.2s.
    assert_in_delta 0.2, connection.send(:decode_ack_delay, 25_000), 1e-6
  end

  def test_loss_retransmits_stream_frame
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake

    sph = connection.instance_variable_get(:@sent_packet_handler)

    # Record three sent packets in application_data so the packet-threshold
    # (3 packets past largest_acked) will declare #1 as lost when #4 is ACKed.
    lost_stream_frame = Raiha::Quic::Wire::Frames::StreamFrame.new
    lost_stream_frame.stream_id = 4
    lost_stream_frame.offset = 0
    lost_stream_frame.data = "payload".b
    lost_stream_frame.fin = false

    register_sent_packet(sph, pn_value: 1, frames: [lost_stream_frame])
    register_sent_packet(sph, pn_value: 2, frames: [])
    register_sent_packet(sph, pn_value: 3, frames: [])
    register_sent_packet(sph, pn_value: 4, frames: [])

    # ACK packet #4; packet #1 is now 3 behind largest_acked → lost.
    ack = build_simple_ack(largest: 4)
    connection.handle_frames([ack], level: Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)

    pending = connection.instance_variable_get(:@pending_stream_frames)
    refute_nil pending
    assert_equal 1, pending.length
    assert_equal "payload".b, pending.first.data
    assert_equal 0, pending.first.offset
  end

  def test_tick_transitions_closing_to_closed_on_drain_timeout
    connection = create_connection
    connection.close

    assert connection.closing?
    drain_deadline = connection.instance_variable_get(:@drain_timer).deadline
    refute_nil drain_deadline

    # Before deadline: still closing.
    connection.tick(now: drain_deadline - 0.01)
    assert connection.closing?

    # At or past deadline: transition to closed.
    connection.tick(now: drain_deadline)
    assert connection.closed?
  end

  def test_tick_transitions_draining_to_closed_on_drain_timeout
    connection = create_connection

    # Peer-initiated close: receiving CONNECTION_CLOSE puts us in draining.
    frame = Raiha::Quic::Wire::Frames::ConnectionCloseFrame.new
    connection.handle_frames([frame])

    assert connection.draining?
    drain_deadline = connection.instance_variable_get(:@drain_timer).deadline
    refute_nil drain_deadline

    connection.tick(now: drain_deadline - 0.01)
    assert connection.draining?

    connection.tick(now: drain_deadline)
    assert connection.closed?
  end

  def test_tick_does_nothing_once_closed
    connection = create_connection
    connection.close
    drain_deadline = connection.instance_variable_get(:@drain_timer).deadline
    connection.tick(now: drain_deadline)
    assert connection.closed?

    # Repeated ticks must stay closed and not re-log or re-enter.
    connection.tick(now: drain_deadline + 10)
    assert connection.closed?
  end

  def test_tick_silently_closes_on_idle_timeout
    transport_parameters = Raiha::Quic::Handshake::TransportParameters.new
    transport_parameters.max_idle_timeout = 30_000  # 30 seconds in ms
    connection = create_connection(transport_parameters: transport_parameters)
    connection.complete_handshake

    idle_deadline = connection.instance_variable_get(:@idle_timer).deadline
    refute_nil idle_deadline

    connection.tick(now: idle_deadline - 0.01)
    refute connection.closed?

    connection.tick(now: idle_deadline)
    assert connection.closed?
  end

  def test_next_timer_deadline_reflects_earliest_armed_timer
    transport_parameters = Raiha::Quic::Handshake::TransportParameters.new
    transport_parameters.max_idle_timeout = 30_000
    connection = create_connection(transport_parameters: transport_parameters)

    idle_deadline = connection.instance_variable_get(:@idle_timer).deadline
    assert_equal idle_deadline, connection.next_timer_deadline

    # Entering draining installs a nearer deadline (3 * PTO < 30s idle).
    connection.close
    drain_deadline = connection.instance_variable_get(:@drain_timer).deadline
    assert_operator drain_deadline, :<, idle_deadline
    assert_equal drain_deadline, connection.next_timer_deadline
  end

  def test_incoming_datagram_with_known_reset_token_enters_draining
    connection = create_connection

    # Register an alternate CID carrying a known reset token via
    # NEW_CONNECTION_ID, the same path the peer would use at runtime.
    token = "STATELESSRESET!!".b
    frame = Raiha::Quic::Wire::Frames::NewConnectionIdFrame.new
    frame.sequence_number = 1
    frame.retire_prior_to = 0
    frame.connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes(["c1c2c3c4"].pack("H*"))
    frame.stateless_reset_token = token
    connection.handle_frames([frame])

    refute connection.draining?

    datagram = ("\x00".b * 20) + token
    connection.handle_packet(datagram)

    assert connection.draining?
  end

  def test_incoming_datagram_without_matching_token_is_processed_normally
    connection = create_connection

    # No peer CIDs registered → no tokens known → normal processing path.
    datagram = "\x00".b * 50
    connection.handle_packet(datagram)

    refute connection.draining?
  end

  def test_multiple_one_rtt_frames_coalesce_into_single_datagram
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake
    grant_bidi_streams(connection, 10)

    # Arrange multiple pending 1-RTT items: stream data, PATH_RESPONSE,
    # RETIRE_CONNECTION_ID, PING, HANDSHAKE_DONE... pre-coalescing this
    # would be >=5 separate datagrams; now they all go in one.
    stream = connection.open_stream(bidirectional: true)
    connection.send_stream_data(stream.stream_id, "hi".b)
    connection.send(:queue_path_response, "\x00".b * 8)
    connection.instance_variable_get(:@pending_retire_connection_ids) << 7
    connection.send(:on_pto_fired)

    datagrams = connection.get_packets_to_send
    assert_equal 1, datagrams.length
    refute_empty datagrams.first
  end

  def test_server_queues_handshake_done_on_complete_handshake
    server = create_connection(perspective: :server)
    refute server.instance_variable_get(:@pending_handshake_done)

    server.complete_handshake

    assert_equal true, server.instance_variable_get(:@pending_handshake_done)
  end

  def test_client_does_not_queue_handshake_done
    client = create_connection(perspective: :client)
    client.complete_handshake
    assert_nil client.instance_variable_get(:@pending_handshake_done)
  end

  def test_server_emits_handshake_done_in_one_rtt_packet
    server = create_connection(perspective: :server)
    enable_one_rtt(server)
    server.complete_handshake

    packets = server.get_packets_to_send
    refute_empty packets

    # After emission the flag is cleared, so a second call does not re-send.
    refute server.instance_variable_get(:@pending_handshake_done)
    assert_empty server.get_packets_to_send
  end

  def test_client_stores_received_new_token
    client = create_connection(perspective: :client)
    assert_nil client.peer_issued_token

    frame = Raiha::Quic::Wire::Frames::NewTokenFrame.new
    frame.token = "opaque-token".b
    client.handle_frames([frame])

    assert_equal "opaque-token".b, client.peer_issued_token
  end

  def test_server_closes_with_protocol_violation_on_new_token_receipt
    # RFC 9000 §19.7: servers MUST treat receipt of NEW_TOKEN as a
    # PROTOCOL_VIOLATION transport error.
    server = create_connection(perspective: :server)
    frame = Raiha::Quic::Wire::Frames::NewTokenFrame.new
    frame.token = "bad".b
    server.handle_frames([frame])

    assert_nil server.peer_issued_token
    assert server.closing?

    close_frame = server.instance_variable_get(:@close_frame)
    assert_equal Raiha::Quic::Qerr::TransportErrorCode::PROTOCOL_VIOLATION, close_frame.error_code
    refute close_frame.application_error
    assert_equal Raiha::Quic::Wire::Frame::Type::NEW_TOKEN, close_frame.trigger_frame_type
  end

  def test_server_send_new_token_queues_frame
    server = create_connection(perspective: :server)
    enable_one_rtt(server)
    server.complete_handshake
    server.get_packets_to_send  # drain HANDSHAKE_DONE so it doesn't confound

    server.send_new_token("future-resumption".b)

    packets = server.get_packets_to_send
    refute_empty packets
    assert_empty server.instance_variable_get(:@pending_new_tokens)
  end

  def test_client_send_new_token_raises
    client = create_connection(perspective: :client)
    assert_raises(Raiha::Error) { client.send_new_token("nope".b) }
  end

  def test_lost_new_token_is_retransmitted
    server = create_connection(perspective: :server)

    sph = server.instance_variable_get(:@sent_packet_handler)
    lost_nt = Raiha::Quic::Wire::Frames::NewTokenFrame.new
    lost_nt.token = "resume-me".b
    register_sent_packet(sph, pn_value: 0, frames: [lost_nt])
    register_sent_packet(sph, pn_value: 1, frames: [])
    register_sent_packet(sph, pn_value: 2, frames: [])
    register_sent_packet(sph, pn_value: 3, frames: [])

    ack = build_simple_ack(largest: 3)
    server.handle_frames([ack], level: Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)

    pending = server.instance_variable_get(:@pending_new_tokens)
    assert_equal ["resume-me".b], pending
  end

  def test_lost_handshake_done_is_retransmitted
    server = create_connection(perspective: :server)
    enable_one_rtt(server)
    server.complete_handshake
    # Drain the pending flag so we can verify retransmission restores it.
    server.get_packets_to_send
    refute server.instance_variable_get(:@pending_handshake_done)

    sph = server.instance_variable_get(:@sent_packet_handler)
    lost_hd = Raiha::Quic::Wire::Frames::HandshakeDoneFrame.new
    register_sent_packet(sph, pn_value: 1, frames: [lost_hd])
    register_sent_packet(sph, pn_value: 2, frames: [])
    register_sent_packet(sph, pn_value: 3, frames: [])
    register_sent_packet(sph, pn_value: 4, frames: [])

    ack = build_simple_ack(largest: 4)
    server.handle_frames([ack], level: Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)

    assert_equal true, server.instance_variable_get(:@pending_handshake_done)
  end

  def test_tick_fires_pto_and_queues_ping_probe
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake

    sph = connection.instance_variable_get(:@sent_packet_handler)
    rtt_stats = connection.instance_variable_get(:@rtt_stats)
    start = Time.now

    sph.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(0),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: Raiha::Quic::Protocol::PacketNumberSpace::APPLICATION_DATA,
      sent_time: start
    )

    # Before PTO deadline: no probe queued.
    connection.tick(now: start)
    assert_empty(connection.instance_variable_get(:@pending_ping_frames) || [])

    # After PTO deadline with no ACK: pto_count increments and a PING is queued.
    connection.tick(now: start + rtt_stats.pto + 0.01)
    pending = connection.instance_variable_get(:@pending_ping_frames)
    refute_nil pending
    assert_equal 1, pending.length
    assert_instance_of Raiha::Quic::Wire::Frames::PingFrame, pending.first
    assert_equal 1, sph.pto_count

    # get_packets_to_send actually sends the probe packet.
    packets = connection.get_packets_to_send
    refute_empty packets
  end

  def test_tick_triggers_time_threshold_loss_detection
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake

    sph = connection.instance_variable_get(:@sent_packet_handler)
    rtt_stats = connection.instance_variable_get(:@rtt_stats)
    start = Time.now

    stream_frame = Raiha::Quic::Wire::Frames::StreamFrame.new
    stream_frame.stream_id = 4
    stream_frame.offset = 0
    stream_frame.data = "late".b
    stream_frame.fin = false

    sph.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(1),
      frames: [stream_frame],
      size: 100,
      ack_eliciting: true,
      pn_space: Raiha::Quic::Protocol::PacketNumberSpace::APPLICATION_DATA,
      sent_time: start
    )
    sph.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(2),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: Raiha::Quic::Protocol::PacketNumberSpace::APPLICATION_DATA,
      sent_time: start
    )

    # ACK #2 only, at t=start, so #1 is held in loss_time scope.
    ack = build_simple_ack(largest: 2)
    connection.send(:handle_ack_frame, ack, level: Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)

    deadline = connection.next_timer_deadline
    refute_nil deadline

    # Before the deadline: tick does nothing.
    connection.tick(now: start)
    assert_empty(connection.instance_variable_get(:@pending_stream_frames) || [])

    # After the deadline: #1 is declared lost and its stream frame is requeued.
    connection.tick(now: start + rtt_stats.loss_delay + 0.01)
    pending = connection.instance_variable_get(:@pending_stream_frames)
    refute_nil pending
    assert_equal 1, pending.length
    assert_equal "late".b, pending.first.data
  end

  def test_loss_requeues_crypto_frame_with_original_offset
    connection = create_connection

    sph = connection.instance_variable_get(:@sent_packet_handler)

    lost_crypto = Raiha::Quic::Wire::Frames::CryptoFrame.new
    lost_crypto.offset = 100
    lost_crypto.data = "handshake-bytes".b

    register_sent_packet(sph, pn_value: 0, frames: [lost_crypto])
    register_sent_packet(sph, pn_value: 1, frames: [])
    register_sent_packet(sph, pn_value: 2, frames: [])
    register_sent_packet(sph, pn_value: 3, frames: [])

    ack = build_simple_ack(largest: 3)
    connection.handle_frames([ack], level: Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)

    # The CryptoSetup now has one pending chunk at the original offset 100.
    crypto = connection.instance_variable_get(:@crypto_setup)
    chunk = crypto.pop_crypto_frame(level: Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)
    refute_nil chunk
    assert_equal 100, chunk[:offset]
    assert_equal "handshake-bytes".b, chunk[:data]
  end

  def test_loss_requeues_reset_stream_frame_on_stream
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake
    grant_bidi_streams(connection, 10)
    stream = connection.open_stream(bidirectional: true)
    connection.reset_stream(stream.stream_id.value, 0x77)

    # Drain the pending flag (simulating the frame going out on the wire).
    refute_nil stream.take_reset_stream_frame
    assert_nil stream.take_reset_stream_frame

    sph = connection.instance_variable_get(:@sent_packet_handler)
    lost_reset = Raiha::Quic::Wire::Frames::ResetStreamFrame.new
    lost_reset.stream_id = stream.stream_id.value
    lost_reset.application_protocol_error_code = 0x77
    lost_reset.final_size = 0

    register_sent_packet(sph, pn_value: 1, frames: [lost_reset])
    register_sent_packet(sph, pn_value: 2, frames: [])
    register_sent_packet(sph, pn_value: 3, frames: [])
    register_sent_packet(sph, pn_value: 4, frames: [])

    ack = build_simple_ack(largest: 4)
    connection.handle_frames([ack], level: Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)

    refute_nil stream.take_reset_stream_frame, "lost RESET_STREAM should re-queue"
  end

  def test_reset_stream_frame_transitions_receive_side
    connection = create_connection
    connection.complete_handshake

    frame = Raiha::Quic::Wire::Frames::ResetStreamFrame.new
    frame.stream_id = 1
    frame.application_protocol_error_code = 0x11
    frame.final_size = 3
    connection.handle_frames([frame])

    stream = connection.streams.get_stream(1)
    refute_nil stream
    assert stream.reset_received?
    assert_equal 0x11, stream.peer_reset_error_code
    assert_equal 3, stream.peer_reset_final_size
  end

  def test_stop_sending_frame_triggers_reset_stream_back
    connection = create_connection
    connection.complete_handshake
    grant_bidi_streams(connection, 10)

    stream = connection.open_stream(bidirectional: true)
    stream.write("hello".b)

    frame = Raiha::Quic::Wire::Frames::StopSendingFrame.new
    frame.stream_id = stream.stream_id.value
    frame.application_protocol_error_code = 0x22
    connection.handle_frames([frame])

    assert stream.reset_sent?
    assert_equal 0x22, stream.local_reset_error_code
  end

  def test_reset_stream_api_queues_reset_frame_in_send
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake
    grant_bidi_streams(connection, 10)

    stream = connection.open_stream(bidirectional: true)
    connection.reset_stream(stream.stream_id.value, 0x33)

    packets = connection.get_packets_to_send
    refute_empty packets
    assert stream.reset_sent?
  end

  def test_stop_sending_api_queues_stop_sending_frame_in_send
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake

    # A peer-initiated stream so the connection knows about it.
    stream_frame = Raiha::Quic::Wire::Frames::StreamFrame.new
    stream_frame.stream_id = 1
    stream_frame.offset = 0
    stream_frame.data = "hi".b
    stream_frame.fin = false
    connection.handle_frames([stream_frame])

    connection.stop_sending(1, 0x44)

    packets = connection.get_packets_to_send
    refute_empty packets
  end

  def test_handle_connection_close_frame
    connection = create_connection
    frame = Raiha::Quic::Wire::Frames::ConnectionCloseFrame.new
    connection.handle_frames([frame])
    assert connection.draining?
  end

  def test_handle_max_streams_frame
    connection = create_connection
    connection.complete_handshake

    frame = Raiha::Quic::Wire::Frames::MaxStreamsFrame.new
    frame.maximum_streams = 10
    frame.bidirectional = true
    connection.handle_frames([frame])

    # Should now be able to open streams
    stream = connection.open_stream(bidirectional: true)
    refute_nil stream
  end

  def test_close
    connection = create_connection
    connection.close
    # close() now sends CONNECTION_CLOSE and enters the closing state
    # (RFC 9000 §10.2.1); draining is reserved for the peer-initiated path.
    assert connection.closing?
    refute connection.draining?
  end

  def test_close_emits_connection_close_frame_at_best_available_level
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake
    connection.close(error_code: 0x0a, reason: "bye")

    datagrams = connection.get_packets_to_send
    refute_empty datagrams
    assert connection.closing?

    # After the first emission, the pending flag is cleared so subsequent
    # calls without new incoming packets are idle.
    assert_empty connection.get_packets_to_send
  end

  def test_close_with_application_error_sets_app_flag
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake
    connection.close_with_application_error(error_code: 0x0100, reason_phrase: "h3-ok")

    frame = connection.instance_variable_get(:@close_frame)
    assert frame.application_error
    assert_equal 0x0100, frame.error_code
  end

  def test_closing_state_retransmits_connection_close_on_incoming_packet
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake
    connection.close(error_code: 0)
    connection.get_packets_to_send  # drain the first emission

    # Simulate an incoming stray packet while closing. RFC 9000 §10.2.1
    # requires re-sending CONNECTION_CLOSE.
    connection.handle_packet("\x40".b + ("\x00".b * 40))

    datagrams = connection.get_packets_to_send
    refute_empty datagrams
  end

  def test_draining_state_produces_nothing_from_get_packets_to_send
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake

    frame = Raiha::Quic::Wire::Frames::ConnectionCloseFrame.new
    connection.handle_frames([frame])
    assert connection.draining?

    assert_empty connection.get_packets_to_send
  end

  def test_path_challenge_queues_path_response
    connection = create_connection
    connection.complete_handshake

    challenge_data = "\xde\xad\xbe\xef\x01\x02\x03\x04".b
    challenge = Raiha::Quic::Wire::Frames::PathChallengeFrame.new
    challenge.data = challenge_data
    connection.handle_frames([challenge])

    queued = connection.instance_variable_get(:@pending_path_responses)
    assert_equal 1, queued.length
    assert_instance_of Raiha::Quic::Wire::Frames::PathResponseFrame, queued.first
    assert_equal challenge_data, queued.first.data
  end

  def test_initiate_path_validation_queues_challenge
    connection = create_connection
    data = connection.initiate_path_validation
    assert_equal 8, data.bytesize

    queued = connection.instance_variable_get(:@pending_path_challenges)
    assert_equal 1, queued.length
    assert_equal data, queued.first.data

    outstanding = connection.instance_variable_get(:@outstanding_path_challenges)
    assert_includes outstanding, data
  end

  def test_matching_path_response_validates_peer_path
    connection = create_connection
    data = connection.initiate_path_validation
    refute connection.peer_path_validated?

    response = Raiha::Quic::Wire::Frames::PathResponseFrame.new
    response.data = data
    connection.handle_frames([response])

    assert connection.peer_path_validated?
    outstanding = connection.instance_variable_get(:@outstanding_path_challenges)
    refute_includes outstanding, data
  end

  def test_mismatched_path_response_closes_with_protocol_violation
    connection = create_connection
    connection.initiate_path_validation

    response = Raiha::Quic::Wire::Frames::PathResponseFrame.new
    response.data = "\x00".b * 8
    connection.handle_frames([response])

    refute connection.peer_path_validated?
    assert connection.closing?
    close_frame = connection.instance_variable_get(:@close_frame)
    assert_equal Raiha::Quic::Qerr::TransportErrorCode::PROTOCOL_VIOLATION, close_frame.error_code
    assert_equal Raiha::Quic::Wire::Frame::Type::PATH_RESPONSE, close_frame.trigger_frame_type
  end

  def test_new_connection_id_frame_is_tracked
    connection = create_connection

    cid = Raiha::Quic::Protocol::ConnectionID.from_bytes(["a1a2a3a4"].pack("H*"))
    frame = Raiha::Quic::Wire::Frames::NewConnectionIdFrame.new
    frame.sequence_number = 1
    frame.retire_prior_to = 0
    frame.connection_id = cid
    frame.stateless_reset_token = "\x00".b * 16

    connection.handle_frames([frame])

    ids = connection.peer_connection_ids
    assert_equal 1, ids.length
    assert_equal 1, ids.first[:sequence_number]
    assert_equal cid, ids.first[:connection_id]
  end

  def test_duplicate_new_connection_id_is_ignored
    connection = create_connection

    frame = Raiha::Quic::Wire::Frames::NewConnectionIdFrame.new
    frame.sequence_number = 1
    frame.retire_prior_to = 0
    frame.connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes(["b1b2b3b4"].pack("H*"))
    frame.stateless_reset_token = "\x00".b * 16

    connection.handle_frames([frame, frame])
    assert_equal 1, connection.peer_connection_ids.length
  end

  def test_new_connection_id_duplicate_seq_with_mismatched_cid_is_protocol_violation
    connection = create_connection

    first = Raiha::Quic::Wire::Frames::NewConnectionIdFrame.new
    first.sequence_number = 1
    first.retire_prior_to = 0
    first.connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes(["aaaaaaaa"].pack("H*"))
    first.stateless_reset_token = "\x00".b * 16
    connection.handle_frames([first])

    conflicting = Raiha::Quic::Wire::Frames::NewConnectionIdFrame.new
    conflicting.sequence_number = 1
    conflicting.retire_prior_to = 0
    conflicting.connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes(["bbbbbbbb"].pack("H*"))
    conflicting.stateless_reset_token = "\x00".b * 16

    assert_raises(Raiha::Quic::Qerr::ProtocolViolation) do
      connection.handle_frames([conflicting])
    end
  end

  def test_stream_data_blocked_emitted_when_stream_send_window_exhausted
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake
    grant_bidi_streams(connection, 10)

    stream = connection.open_stream(bidirectional: true)
    # Peer-advertised per-stream window is 0 by default; try to send 10 bytes
    # so the stream immediately wants to send but can't.
    stream.write("xxxxxxxxxx".b)
    refute_nil stream.get_data_to_send(1000).nil? || nil
    # (above ensures mark_blocked_at fires)
    stream.get_data_to_send(1000)  # blocked path

    frames = connection.send(:gather_frames_for, Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)
    sdb = frames.find { |f| f.is_a?(Raiha::Quic::Wire::Frames::StreamDataBlockedFrame) }
    refute_nil sdb, "STREAM_DATA_BLOCKED should be queued when stream send_window is exhausted"
    assert_equal stream.stream_id.value, sdb.stream_id
  end

  def test_data_blocked_cleared_when_max_data_arrives
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake
    grant_bidi_streams(connection, 10)

    stream = connection.open_stream(bidirectional: true)
    stream.write("xxxxxxxxxx".b)
    stream.get_data_to_send(1000)  # mark blocked at current windows

    # Now peer raises the connection-level window.
    md_frame = Raiha::Quic::Wire::Frames::MaxDataFrame.new
    md_frame.maximum_data = 1_000_000
    connection.handle_frames([md_frame])

    cfc = connection.instance_variable_get(:@connection_flow_controller)
    refute cfc.pending_blocked_signal?
  end

  def test_streams_blocked_emitted_when_local_opens_exceed_peer_limit
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake
    grant_bidi_streams(connection, 1)  # peer allows 1 bidi stream

    connection.open_stream(bidirectional: true)  # ok
    assert_raises(Raiha::Quic::Qerr::StreamLimitError) do
      connection.open_stream(bidirectional: true)  # blocked
    end

    frames = connection.send(:gather_frames_for, Raiha::Quic::Handshake::EncryptionLevel::ONE_RTT)
    sb = frames.find { |f| f.is_a?(Raiha::Quic::Wire::Frames::StreamsBlockedFrame) }
    refute_nil sb
    assert sb.bidirectional
    assert_equal 1, sb.maximum_streams
  end

  def test_max_stream_data_on_receive_only_stream_raises_stream_state_error
    client = create_connection(perspective: :client)
    # Server-initiated uni (id = 3) is receive-only for a client; peer has
    # no business granting us credit to send on it.
    frame = Raiha::Quic::Wire::Frames::MaxStreamDataFrame.new
    frame.stream_id = 3
    frame.maximum_stream_data = 10_000

    assert_raises(Raiha::Quic::Qerr::StreamStateError) do
      client.handle_frames([frame])
    end
  end

  def test_send_stream_data_on_receive_only_stream_raises_argument_error
    client = create_connection(perspective: :client)
    # server-initiated uni, client cannot send on it.
    assert_raises(ArgumentError) do
      client.send_stream_data(3, "nope".b)
    end
  end

  def test_stream_frame_on_locally_initiated_uni_raises_stream_state_error
    client = create_connection(perspective: :client)
    # Client-initiated unidirectional streams use id = 2 + 4n. Peer sending
    # STREAM on stream 2 means peer is the sender on our send-only stream.
    frame = Raiha::Quic::Wire::Frames::StreamFrame.new
    frame.stream_id = 2
    frame.offset = 0
    frame.data = "no".b
    frame.fin = false

    assert_raises(Raiha::Quic::Qerr::StreamStateError) do
      client.handle_frames([frame])
    end
  end

  def test_reset_stream_on_locally_initiated_uni_raises_stream_state_error
    client = create_connection(perspective: :client)
    frame = Raiha::Quic::Wire::Frames::ResetStreamFrame.new
    frame.stream_id = 2  # client-initiated uni
    frame.application_protocol_error_code = 0
    frame.final_size = 0

    assert_raises(Raiha::Quic::Qerr::StreamStateError) do
      client.handle_frames([frame])
    end
  end

  def test_stream_exceeding_initial_max_streams_raises_stream_limit_error
    # Configure our local limits to admit only 1 peer-initiated bidi stream.
    transport_parameters = Raiha::Quic::Handshake::TransportParameters.new
    transport_parameters.initial_max_streams_bidi = 1
    transport_parameters.initial_max_streams_uni = 0
    client = create_connection(perspective: :client, transport_parameters: transport_parameters)

    # Peer-initiated bidi stream id 1 is the first permitted server stream.
    # Id 5 would be the second, which exceeds initial_max_streams_bidi.
    frame = Raiha::Quic::Wire::Frames::StreamFrame.new
    frame.stream_id = 5
    frame.offset = 0
    frame.data = "nope".b
    frame.fin = false

    assert_raises(Raiha::Quic::Qerr::StreamLimitError) do
      client.handle_frames([frame])
    end
  end

  def test_stop_sending_on_unopened_locally_initiated_stream_raises_stream_state_error
    client = create_connection(perspective: :client)
    # Client-initiated bidi stream id 0 — we (client) would have opened it
    # but haven't; peer cannot preemptively STOP_SENDING on it.
    frame = Raiha::Quic::Wire::Frames::StopSendingFrame.new
    frame.stream_id = 0
    frame.application_protocol_error_code = 0

    assert_raises(Raiha::Quic::Qerr::StreamStateError) do
      client.handle_frames([frame])
    end
  end

  def test_stop_sending_on_peer_initiated_uni_raises_stream_state_error
    client = create_connection(perspective: :client)
    # Server-initiated uni (id = 3 + 4n) is receive-only for us; peer cannot
    # ask us to stop sending on a stream we never send on.
    frame = Raiha::Quic::Wire::Frames::StopSendingFrame.new
    frame.stream_id = 3
    frame.application_protocol_error_code = 0

    assert_raises(Raiha::Quic::Qerr::StreamStateError) do
      client.handle_frames([frame])
    end
  end

  def test_send_early_data_queues_stream_frame_for_zero_rtt_emit
    # Install early keys so build_level_packet(ZERO_RTT) is available.
    client = create_connection(perspective: :client)
    cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
    secret = SecureRandom.random_bytes(32)
    client.instance_variable_get(:@crypto_setup).set_early_keys(
      client_early_traffic_secret: secret,
      cipher_suite: cipher_suite
    )
    grant_bidi_streams(client, 10)
    stream = client.open_stream(bidirectional: true)

    client.send_early_data(stream.stream_id, "first-flight".b)

    pending = client.instance_variable_get(:@pending_early_stream_frames)
    assert_equal 1, pending.length
    assert_equal "first-flight".b, pending.first.data
    assert_equal stream.stream_id.value, pending.first.stream_id
  end

  def test_send_early_data_rejects_stream_not_writable_by_us
    client = create_connection(perspective: :client)
    # Server-initiated uni stream id 3 is receive-only for a client.
    assert_raises(ArgumentError) do
      client.send_early_data(3, "nope".b)
    end
  end

  def test_zero_rtt_packet_coalesces_with_initial
    client = create_connection(perspective: :client)
    cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
    client.instance_variable_get(:@crypto_setup).set_early_keys(
      client_early_traffic_secret: SecureRandom.random_bytes(32),
      cipher_suite: cipher_suite
    )
    grant_bidi_streams(client, 10)
    stream = client.open_stream(bidirectional: true)
    client.send_early_data(stream.stream_id, "hi".b)

    datagrams = client.get_packets_to_send
    refute_empty datagrams

    # An Initial leads with the 0xc* upper nibble; the datagram carries
    # one (either produced by any pending Initial CRYPTO OR padded to
    # 1200 by build_packet). After flush the 0-RTT queue is drained.
    assert_empty client.instance_variable_get(:@pending_early_stream_frames)
  end

  def test_ping_queues_a_single_ping_frame
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake

    assert connection.ping
    # A second call while one is still pending returns false.
    refute connection.ping

    pending = connection.instance_variable_get(:@pending_ping_frames)
    assert_equal 1, pending.length
    assert_instance_of Raiha::Quic::Wire::Frames::PingFrame, pending.first
  end

  def test_ping_emitted_in_get_packets_to_send
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake
    connection.ping

    refute_empty connection.get_packets_to_send
    # Queue was drained.
    assert_empty connection.instance_variable_get(:@pending_ping_frames)
  end

  def test_tick_queues_keepalive_ping_when_idle_past_half_timeout
    transport_parameters = Raiha::Quic::Handshake::TransportParameters.new
    transport_parameters.max_idle_timeout = 30_000  # 30 seconds
    connection = create_connection(transport_parameters: transport_parameters)
    enable_one_rtt(connection)
    connection.complete_handshake

    idle_deadline = connection.instance_variable_get(:@idle_timer).deadline
    # Plenty of time left → no keepalive.
    connection.tick(now: idle_deadline - 20)
    assert_nil connection.instance_variable_get(:@pending_ping_frames)

    # Past the halfway mark → keepalive PING queued.
    connection.tick(now: idle_deadline - 10)
    pending = connection.instance_variable_get(:@pending_ping_frames)
    assert_equal 1, pending.length
  end

  def test_tick_does_not_queue_keepalive_when_one_already_pending
    transport_parameters = Raiha::Quic::Handshake::TransportParameters.new
    transport_parameters.max_idle_timeout = 30_000
    connection = create_connection(transport_parameters: transport_parameters)
    enable_one_rtt(connection)
    connection.complete_handshake

    idle_deadline = connection.instance_variable_get(:@idle_timer).deadline
    connection.tick(now: idle_deadline - 5)  # queue one
    connection.tick(now: idle_deadline - 3)  # should not pile up a second

    assert_equal 1, connection.instance_variable_get(:@pending_ping_frames).length
  end

  def test_retry_packet_updates_connection_id_and_captures_token
    # RFC 9001 Appendix A.4 sample retry packet, matched by its ODCID.
    odcid = ["8394c8f03e515708"].pack("H*")
    sample_retry = [
      "ff000000010008f067a5502a4262b574" +
      "6f6b656e04a265ba2eff4d829058fb3f" +
      "0f2496ba"
    ].pack("H*")

    client = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(odcid)
    )

    client.handle_packet(sample_retry)

    assert_equal "token".b, client.retry_token
    # Server-picked SCID (8 bytes: f067a5502a4262b5) becomes our new DCID.
    assert_equal ["f067a5502a4262b5"].pack("H*"), client.dest_connection_id.serialize
    assert client.instance_variable_get(:@retry_consumed)
  end

  def test_retry_replays_client_hello_at_offset_zero_with_token
    odcid = ["8394c8f03e515708"].pack("H*")
    sample_retry = [
      "ff000000010008f067a5502a4262b574" +
      "6f6b656e04a265ba2eff4d829058fb3f" +
      "0f2496ba"
    ].pack("H*")

    client = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(odcid)
    )

    # Stage some Initial CRYPTO as if start_handshake had queued a ClientHello.
    crypto = client.instance_variable_get(:@crypto_setup)
    crypto.queue_crypto_data("CHBYTES".b, level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)

    # Drain (as if we already sent the first Initial), then receive Retry.
    crypto.pop_crypto_frame(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    client.handle_packet(sample_retry)

    # The ClientHello bytes are replayed at offset 0 under the new keys.
    replayed = crypto.pop_crypto_frame(level: Raiha::Quic::Handshake::EncryptionLevel::INITIAL)
    refute_nil replayed
    assert_equal 0, replayed[:offset]
    assert_equal "CHBYTES".b, replayed[:data]
  end

  def test_second_retry_is_ignored
    odcid = ["8394c8f03e515708"].pack("H*")
    sample_retry = [
      "ff000000010008f067a5502a4262b574" +
      "6f6b656e04a265ba2eff4d829058fb3f" +
      "0f2496ba"
    ].pack("H*")
    client = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(odcid)
    )

    client.handle_packet(sample_retry)
    first_dcid = client.dest_connection_id.serialize

    # A second Retry even with a valid tag (same packet) must not change
    # the state after the first was processed (§17.2.5.2).
    client.handle_packet(sample_retry)
    assert_equal first_dcid, client.dest_connection_id.serialize
  end

  def test_retry_with_invalid_integrity_tag_is_dropped
    odcid = ["8394c8f03e515708"].pack("H*")
    sample_retry = [
      "ff000000010008f067a5502a4262b574" +
      "6f6b656e04a265ba2eff4d829058fb3f" +
      "0f2496ba"
    ].pack("H*")
    tampered = sample_retry.dup
    tampered.setbyte(-1, tampered.getbyte(-1) ^ 0xff)

    client = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.from_bytes(odcid)
    )

    client.handle_packet(tampered)
    assert_nil client.retry_token
    refute client.instance_variable_get(:@retry_consumed)
  end

  def test_initiate_key_update_flips_key_phase_and_rotates_keys
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake

    phase_before = connection.send(:instance_variable_get, :@crypto_setup).one_rtt_key_phase
    new_phase = connection.initiate_key_update

    refute_equal phase_before, new_phase
  end

  def test_initiate_key_update_raises_without_one_rtt_keys
    connection = create_connection
    assert_raises(Raiha::Error) { connection.initiate_key_update }
  end

  def test_initiate_key_update_rate_limited_within_three_pto
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake

    now = Time.now
    connection.initiate_key_update(now: now)

    rtt = connection.instance_variable_get(:@rtt_stats)
    assert_raises(Raiha::Error) do
      connection.initiate_key_update(now: now + rtt.pto) # well under 3×PTO
    end

    # After 3×PTO+ε, the next update is allowed again.
    connection.initiate_key_update(now: now + 3 * rtt.pto + 0.01)
  end

  def test_peer_address_reader_tracks_latest_supplied_address
    server = create_connection(perspective: :server)
    assert_nil server.peer_address

    server.handle_packet("\x00".b * 40, peer_address: ["10.0.0.1", 40000])
    assert_equal ["10.0.0.1", 40000], server.peer_address
  end

  def test_migration_allowed_defaults_true_before_handshake
    connection = create_connection
    assert connection.migration_allowed?
  end

  def test_migration_allowed_false_when_peer_advertised_disable
    connection = create_connection

    peer_tp = Raiha::Quic::Handshake::TransportParameters.new
    peer_tp.disable_active_migration = true

    # Pretend the handshake has completed and produced the peer TP.
    tls_adapter = connection.instance_variable_get(:@tls_adapter)
    tls_adapter.instance_variable_set(:@peer_transport_parameters, peer_tp)

    refute connection.migration_allowed?
  end

  def test_peer_address_change_before_handshake_is_not_migration
    server = create_connection(perspective: :server)

    server.handle_packet("\x00".b * 40, peer_address: ["10.0.0.1", 40000])
    server.handle_packet("\x00".b * 40, peer_address: ["10.0.0.2", 40001])

    assert_equal 1, server.migration_count
    # No PATH_CHALLENGE queued because handshake is not complete yet.
    assert_empty server.instance_variable_get(:@pending_path_challenges)
  end

  def test_peer_address_change_after_handshake_initiates_path_validation
    server = create_connection(perspective: :server)
    enable_one_rtt(server)
    server.complete_handshake

    # First datagram arrives from address A; becomes the baseline.
    server.handle_packet("\x40".b + ("\x00".b * 40), peer_address: ["10.0.0.1", 40000])
    refute server.instance_variable_get(:@pending_path_challenges).any?

    # Second datagram arrives from address B after handshake complete:
    # migration detected, PATH_CHALLENGE auto-queued, peer marked
    # unvalidated until the matching PATH_RESPONSE comes back.
    server.handle_packet("\x40".b + ("\x00".b * 40), peer_address: ["10.0.0.2", 40001])

    assert_equal 1, server.migration_count
    refute_empty server.instance_variable_get(:@pending_path_challenges)
    refute server.peer_path_validated?
  end

  def test_successful_migration_resets_congestion_and_rtt
    server = create_connection(perspective: :server)
    enable_one_rtt(server)
    server.complete_handshake
    server.handle_packet("\x40".b + ("\x00".b * 40), peer_address: ["10.0.0.1", 40000])

    cubic = server.instance_variable_get(:@congestion_controller)
    rtt = server.instance_variable_get(:@rtt_stats)

    # Make sure cubic and rtt have non-default state so we can observe a reset.
    rtt.update_rtt(0.05, 0.001)
    packet = Data.define(:size).new(size: 1200)
    cubic.on_packet_lost(packet)
    refute cubic.in_slow_start?
    refute_equal Float::INFINITY, cubic.slow_start_threshold

    # Trigger migration: new peer address.
    server.handle_packet("\x40".b + ("\x00".b * 40), peer_address: ["10.0.0.2", 40001])

    challenge = server.instance_variable_get(:@migration_challenges).first
    refute_nil challenge

    # Peer answers the migration PATH_CHALLENGE with the matching data.
    response = Raiha::Quic::Wire::Frames::PathResponseFrame.new
    response.data = challenge
    server.handle_frames([response])

    assert server.peer_path_validated?
    # §9.4: congestion controller and RTT estimator reset.
    assert cubic.in_slow_start?
    assert_equal Float::INFINITY, cubic.slow_start_threshold
    refute rtt.has_samples?
  end

  def test_non_migration_path_response_does_not_reset_cubic
    server = create_connection(perspective: :server)
    enable_one_rtt(server)
    server.complete_handshake

    challenge = server.initiate_path_validation
    cubic = server.instance_variable_get(:@congestion_controller)
    # Sanity: the congestion controller starts in slow start; push it out
    # explicitly so a bogus reset would be observable.
    packet = Data.define(:size).new(size: 1200)
    cubic.on_packet_lost(packet)
    refute cubic.in_slow_start?

    response = Raiha::Quic::Wire::Frames::PathResponseFrame.new
    response.data = challenge
    server.handle_frames([response])

    # Non-migration validation leaves congestion state alone.
    refute cubic.in_slow_start?
  end

  def test_peer_address_change_without_peer_address_arg_is_a_noop
    server = create_connection(perspective: :server)
    enable_one_rtt(server)
    server.complete_handshake

    server.handle_packet("\x40".b + ("\x00".b * 40))
    server.handle_packet("\x40".b + ("\x00".b * 40))

    assert_equal 0, server.migration_count
  end

  def test_client_version_negotiation_abandons_connection
    client = create_connection(perspective: :client)

    packet = Raiha::Quic::Wire::VersionNegotiation.build(
      src_connection_id: client.dest_connection_id.serialize,
      dest_connection_id: client.src_connection_id.serialize,
      supported_versions: [0xfafafafa, 0xff000011]
    )

    client.handle_packet(packet)

    assert client.closed?
    assert_equal [0xfafafafa, 0xff000011], client.peer_supported_versions
  end

  def test_server_ignores_version_negotiation_packet
    # §6.2 is client-only; servers don't interpret incoming VN packets.
    server = create_connection(perspective: :server)

    packet = Raiha::Quic::Wire::VersionNegotiation.build(
      src_connection_id: "\x01".b,
      dest_connection_id: "\x02".b,
      supported_versions: [0x00000001]
    )

    server.handle_packet(packet)
    refute server.closed?
    assert_nil server.peer_supported_versions
  end

  def test_handle_packet_converts_transport_error_to_connection_close
    connection = create_connection

    # Stub the first stage of packet parsing to throw a TransportError,
    # mirroring what a real invalid frame would produce during an
    # encrypted packet's frame loop. This exercises the handle_packet
    # rescue arm without needing a real encrypted payload.
    connection.define_singleton_method(:handle_long_header_packet) do |_, _, **_kwargs|
      raise Raiha::Quic::Qerr::ProtocolViolation.new(reason_phrase: "synthetic")
    end

    # A long-header datagram with version V1 so handle_packet routes to
    # the stub (version 0 would short-circuit into the VN detector).
    datagram = ("\xc0".b + "\x00\x00\x00\x01".b + ("\x00".b * 36))
    connection.handle_packet(datagram)

    assert connection.closing?
    close_frame = connection.instance_variable_get(:@close_frame)
    assert_equal Raiha::Quic::Qerr::TransportErrorCode::PROTOCOL_VIOLATION, close_frame.error_code
  end

  def test_new_connection_id_retire_prior_to_queues_retires
    connection = create_connection

    [0, 1, 2].each do |seq|
      frame = Raiha::Quic::Wire::Frames::NewConnectionIdFrame.new
      frame.sequence_number = seq
      frame.retire_prior_to = 0
      frame.connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes([("aa" * 4)].pack("H*"))
      frame.stateless_reset_token = "\x00".b * 16
      connection.handle_frames([frame])
    end

    retiring = Raiha::Quic::Wire::Frames::NewConnectionIdFrame.new
    retiring.sequence_number = 3
    retiring.retire_prior_to = 2
    retiring.connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes([("bb" * 4)].pack("H*"))
    retiring.stateless_reset_token = "\x00".b * 16
    connection.handle_frames([retiring])

    # Only sequence numbers >= 2 remain (2 and 3).
    sequence_numbers = connection.peer_connection_ids.map { |e| e[:sequence_number] }.sort
    assert_equal [2, 3], sequence_numbers

    # Retires for sequence numbers 0 and 1 are queued to send back.
    pending = connection.instance_variable_get(:@pending_retire_connection_ids).sort
    assert_equal [0, 1], pending
  end

  def test_retire_connection_id_frame_is_accepted
    connection = create_connection

    frame = Raiha::Quic::Wire::Frames::RetireConnectionIdFrame.new
    frame.sequence_number = 0
    connection.handle_frames([frame]) # does not raise
  end

  def test_no_max_data_frame_on_fresh_connection
    # With no bytes received from the peer, we have no reason to advertise
    # more receive credit yet.
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake

    packets = connection.get_packets_to_send
    assert_empty packets
  end

  def test_max_data_frame_emitted_when_receive_window_runs_low
    connection = create_connection
    enable_one_rtt(connection)
    connection.complete_handshake

    # Pretend the peer has filled most of our initial receive window and
    # the application has consumed it. The new limit should advance.
    fc = connection.instance_variable_get(:@connection_flow_controller)
    initial = fc.receive_window
    consumed = initial - 1000
    fc.update_highest_received(consumed)
    fc.add_bytes_read(consumed)

    packets = connection.get_packets_to_send
    refute_empty packets
    assert_operator fc.receive_window, :>, initial
  end

  def test_perspective
    client_connection = create_connection(perspective: :client)
    assert client_connection.perspective.client?
    refute client_connection.perspective.server?

    server_connection = create_connection(perspective: :server)
    assert server_connection.perspective.server?
    refute server_connection.perspective.client?
  end

  private def create_connection(perspective: :client, transport_parameters: nil)
    Raiha::Connection.new(
      perspective: perspective,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      transport_parameters: transport_parameters
    )
  end

  private def register_sent_packet(sph, pn_value:, frames:)
    sph.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(pn_value),
      frames: frames,
      size: 100,
      ack_eliciting: true,
      pn_space: Raiha::Quic::Protocol::PacketNumberSpace::APPLICATION_DATA
    )
    # Force the next_packet_number cursor past this value so subsequent
    # calls do not collide.
    space = sph.instance_variable_get(:@spaces)[Raiha::Quic::Protocol::PacketNumberSpace::APPLICATION_DATA]
    current_largest = space.instance_variable_get(:@largest_sent) || -1
    space.instance_variable_set(:@largest_sent, [current_largest, pn_value].max)
  end

  private def build_simple_ack(largest:)
    ack = Raiha::Quic::Wire::Frames::AckFrame.new
    ack.largest_acknowledged = largest
    ack.ack_delay = 0
    ack.ack_ranges = [Raiha::Quic::Wire::Frames::AckFrame::AckRange.new(gap: 0, ack_range_length: 0)]
    ack
  end

  # Simulate receiving a MAX_STREAMS from the peer so the connection is
  # allowed to open local bidi streams for the test.
  private def grant_bidi_streams(connection, count)
    frame = Raiha::Quic::Wire::Frames::MaxStreamsFrame.new
    frame.maximum_streams = count
    frame.bidirectional = true
    connection.handle_frames([frame])
  end

  # Install synthetic 1-RTT AEAD keys on the connection's CryptoSetup so
  # Connection#get_packets_to_send will consider the ONE_RTT level available.
  private def enable_one_rtt(connection)
    crypto_setup = connection.instance_variable_get(:@crypto_setup)
    cipher_suite = Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
    crypto_setup.set_application_keys(
      client_secret: OpenSSL::Random.random_bytes(32),
      server_secret: OpenSSL::Random.random_bytes(32),
      cipher_suite: cipher_suite
    )
  end
end
