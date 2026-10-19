require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"
require "raiha/next/support/quic_recovery"

# 250 "Tracer and qlog": what a connection tells its tracer.
class RaihaNextQUICConnectionTracerTest < Minitest::Test
  include NextQUICPair

  RecordingTracer = NextQUICRecovery::RecordingTracer

  # Every packet sent is told with its header, frames and size, and the
  # peer tells the same packets as received.
  def test_packets_sent_and_received
    client_tracer = RecordingTracer.new
    server_tracer = RecordingTracer.new
    handshake(client_connection(tracer: client_tracer), server_connection(tracer: server_tracer))
    sent = client_tracer.of(:packet_sent)
    first = sent.first
    assert_equal QUIC::Tracer::PacketHeader.new(packet_type: :initial, packet_number: 0, version: QUIC::Version::V1.number,
      dcid: first[:header].dcid, scid: first[:header].scid, key_phase: nil), first[:header]
    assert_equal QUIC::Connection::MIN_INITIAL_DATAGRAM, first[:raw_length]
    assert first[:frames].grep(QUIC::Wire::Frame::Crypto).any?
    received = server_tracer.of(:packet_received)
    assert_equal sent.map { _1[:header] }, received.map { _1[:header] }
    assert_equal sent.map { _1[:raw_length] }, received.map { _1[:raw_length] }
    assert_includes server_tracer.of(:packet_sent).map { _1[:header].packet_type }, :one_rtt
  end

  # A tracer that does not ask for the frames is not given them.
  def test_frames_only_when_asked
    tracer = RecordingTracer.new(frames: false)
    client_connection(tracer:).transmits(now: 0.0)
    assert_equal [nil], tracer.of(:packet_sent).map { _1[:frames] }
  end
end
