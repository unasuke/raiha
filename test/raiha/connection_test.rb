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

  def test_tick_transitions_draining_to_closed_on_drain_timeout
    connection = create_connection
    connection.close

    assert connection.draining?
    drain_deadline = connection.instance_variable_get(:@drain_timer).deadline
    refute_nil drain_deadline

    # Before deadline: still draining.
    connection.tick(now: drain_deadline - 0.01)
    assert connection.draining?

    # At or past deadline: transition to closed.
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
    assert connection.draining?
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

  def test_mismatched_path_response_does_not_validate
    connection = create_connection
    connection.initiate_path_validation

    response = Raiha::Quic::Wire::Frames::PathResponseFrame.new
    response.data = "\x00".b * 8
    connection.handle_frames([response])

    refute connection.peer_path_validated?
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
    assert_equal :client, client_connection.perspective

    server_connection = create_connection(perspective: :server)
    assert_equal :server, server_connection.perspective
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
