require "test_helper"
require "support/quic_pair"
require "support/quic_recovery"

# RFC 9001 "Receiving Out-of-Order Protected Packets": a packet whose keys
# have not come is kept until they do, and opened then.
class RaihaQUICConnectionKeptPacketsTest < Minitest::Test
  include QUICPair

  # The packets of `datagram` as datagrams of their own, with their types.
  def packets(datagram)
    offset = 0
    parts = []
    while offset < datagram.bytesize
      packet = QUIC::Wire::Packet.parse(datagram, offset:, dcid_length: 8)
      parts << [packet.header.type, datagram.byteslice(offset...packet.end_offset)]
      offset = packet.end_offset
    end
    parts
  end

  # A client given the server's Handshake packets before its Initial keeps
  # them and opens them once the Initial brings the keys: the handshake
  # completes with nothing sent again. The time a packet was kept counts
  # in the delay of the ACK of it.
  def test_a_client_keeps_handshake_packets_that_come_first
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection
    client.transmits(now: 0.0).each { server.receive(_1.payload, from: CLIENT, now: 0.0) }
    parts = server.transmits(now: 0.0).flat_map { packets(_1.payload) }
    initial = parts.select { _1.first == :initial }.map(&:last)
    handshake = parts.select { _1.first == :handshake }.map(&:last)
    refute_empty handshake
    handshake.each { client.receive(_1, from: SERVER, now: 0.0) }
    refute client.handshake_complete?
    initial.each { client.receive(_1, from: SERVER, now: 0.05) }
    assert client.handshake_complete?
    acks = client.transmits(now: 0.05).flat_map { packets(_1.payload) }.select { _1.first == :handshake }.map(&:last)
    keys = one_rtt_keys(keylog, "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
    unmasked = QUIC::Wire::Packet.parse(acks.fetch(0), dcid_length: 8).unmask(keys.header_protection, largest: nil)
    ack = QUIC::Wire::Frame.parse(unmasked.open(keys.aead), packet_type: :handshake, ack_delay_exponent: 3)
      .grep(QUIC::Wire::Frame::Ack).first
    assert_in_delta 0.05, ack.delay, 0.001
  end

  # A server given a client's 1-RTT packet before its Finished keeps it,
  # opens nothing of it before the handshake completes, and opens it then.
  def test_a_server_keeps_one_rtt_packets_until_the_handshake_completes
    client = client_connection
    server = server_connection
    client.transmits(now: 0.0).each { server.receive(_1.payload, from: CLIENT, now: 0.0) }
    server.transmits(now: 0.0).each { client.receive(_1.payload, from: SERVER, now: 0.0) }
    stream_id = client.open_stream
    client.stream_write(stream_id, "kept".b, fin: true)
    parts = client.transmits(now: 0.001).flat_map { packets(_1.payload) }
    one_rtt = parts.select { _1.first == :one_rtt }.map(&:last)
    refute_empty one_rtt
    one_rtt.each { server.receive(_1, from: CLIENT, now: 0.001) }
    refute server.handshake_complete?
    assert_raises(QUIC::Error::StreamError) { server.stream_read(stream_id, 100) }
    parts.reject { _1.first == :one_rtt }.each { server.receive(_1.last, from: CLIENT, now: 0.002) }
    assert server.handshake_complete?
    assert_equal "kept".b, server.stream_read(stream_id, 100)
  end

  # Past what is kept, a packet with no keys is dropped, and so is one of a
  # level whose keys are gone.
  def test_what_is_not_kept
    tracer = QUICRecovery::RecordingTracer.new
    client = client_connection(tracer:)
    server = server_connection
    client.transmits(now: 0.0).each { server.receive(_1.payload, from: CLIENT, now: 0.0) }
    flight = server.transmits(now: 0.0).map(&:payload)
    handshake = flight.flat_map { packets(_1) }.find { _1.first == :handshake }.last
    (QUIC::KeptPackets::PACKETS + 1).times { client.receive(handshake, from: SERVER, now: 0.0) }
    assert_equal 1, tracer.of(:packet_dropped).count { _1[:reason] == :key_unavailable }
    flight.each { client.receive(_1, from: SERVER, now: 0.0) }
    handshake(client, server)
    assert client.handshake_confirmed?
    client.receive(handshake, from: SERVER, now: 1.0)
    assert_equal 2, tracer.of(:packet_dropped).count { _1[:reason] == :key_unavailable }
  end
end
