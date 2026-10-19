require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"
require "raiha/next/support/quic_recovery"

# What a connection tells its tracer.
class RaihaNextQUICConnectionTracerTest < Minitest::Test
  include NextQUICPair

  RecordingTracer = NextQUICRecovery::RecordingTracer

  # A tracer that takes TLS's traces too.
  class TLSRecordingTracer < RecordingTracer
    attr_reader :tls

    def initialize(...)
      super
      @tls = []
    end

    def tls_trace(value) = @tls << value
  end

  # TLS's traces go to a tracer with `tls_trace`;
  # one without it is not handed to TLS, which would call it.
  def test_tls_traces
    client_tracer = TLSRecordingTracer.new
    client = client_connection(tracer: client_tracer)
    server = server_connection(tracer: RecordingTracer.new)
    handshake(client, server)
    assert server.handshake_complete?
    assert client_tracer.tls.grep(TLS::Trace::PeerFinishedVerified).any?, client_tracer.tls.inspect
  end

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

  # Each end tells its own transport parameters and the peer's: one's
  # local are the other's remote.
  def test_transport_parameters
    client_tracer = RecordingTracer.new
    server_tracer = RecordingTracer.new
    handshake(client_connection(tracer: client_tracer), server_connection(tracer: server_tracer))
    client = client_tracer.of(:parameters_set)
    server = server_tracer.of(:parameters_set)
    assert_equal [:local, :remote], client.map { _1[:owner] }
    assert_equal [:local, :remote], server.map { _1[:owner] }
    assert_equal client.first[:parameters], server.last[:parameters]
    assert_equal server.first[:parameters], client.last[:parameters]
  end

  def dropped(tracer) =tracer.of(:packet_dropped).map { [_1[:reason], _1[:raw_length]] }

  # Bytes that do not read as a packet are dropped to the end of the
  # datagram.
  def test_a_header_that_does_not_read
    tracer = RecordingTracer.new
    server_connection(tracer:).receive("\x00".b * 50, from: CLIENT, now: 0.0)
    assert_equal [[:invalid, 50]], dropped(tracer)
  end

  def test_a_version_not_supported
    tracer = RecordingTracer.new
    datagram = [0xc0, 0x0a0a0a0a, 0, 0].pack("CNCC") + "\x00".b * 1200
    server_connection(tracer:).receive(datagram, from: CLIENT, now: 0.0)
    assert_equal [[:unsupported, datagram.bytesize]], dropped(tracer)
  end

  # A packet that does not open, and one that comes again.
  def test_a_forged_packet_and_a_duplicate
    tracer = RecordingTracer.new
    server = server_connection(tracer:)
    first = client_connection.transmits(now: 0.0).first.payload
    forged = first.dup
    forged.setbyte(forged.bytesize - 1, forged.getbyte(forged.bytesize - 1) ^ 1)
    server.receive(forged, from: CLIENT, now: 0.0)
    server.receive(first, from: CLIENT, now: 0.0)
    server.receive(first, from: CLIENT, now: 0.0)
    assert_equal [[:decryption_failure, 1200], [:duplicate, 1200]], dropped(tracer)
  end

  # A 1-RTT packet before the keys to read it.
  def test_no_keys_yet
    tracer = RecordingTracer.new
    client = client_connection(tracer:)
    scid = QUIC::Wire::Packet.parse(client.transmits(now: 0.0).first.payload, dcid_length: 8).header.scid
    keys = QUIC::Crypto::Keys.derive(suite: TLS::CipherSuite::TLS_AES_128_GCM_SHA256, secret: "s".b * 32, version: QUIC::Version::V1)
    packet = QUIC::Wire::Packet.seal(QUIC::Wire::ShortHeader.new(dcid: scid), packet_number: 0, packet_number_length: 2,
      payload: "\x01".b * 30, keys:)
    client.receive(packet, from: SERVER, now: 0.0)
    assert_equal [[:key_unavailable, packet.bytesize]], dropped(tracer)
  end

  # A tracer that does not ask for the frames is not given them.
  def test_frames_only_when_asked
    tracer = RecordingTracer.new(frames: false)
    client_connection(tracer:).transmits(now: 0.0)
    assert_equal [nil], tracer.of(:packet_sent).map { _1[:frames] }
  end
end
