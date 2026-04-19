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
