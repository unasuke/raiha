require "test_helper"
require "support/quic_pair"
require "objspace"

# What other implementations of QUIC were broken by over streams, each
# tried on this one: frames that make the peer hold memory or spend CPU it
# decides the amount of, and events the application does not take. The
# limit of retired connection IDs waiting for their acknowledgment is
# tested with PeerConnectionIDs, and DATAGRAMs the application does not
# take with the Connection.
class RaihaQUICKnownVulnerabilitiesStreamsTest < Minitest::Test
  include QUICPair

  # A server done with the handshake, and its connection ID.
  def connected_server
    @keylog = Keylog.new
    client = client_connection(keylog: @keylog)
    server = server_connection
    first = client.transmits(now: 0.0).first.payload
    server.receive(first, from: CLIENT, now: 0.0)
    reply = server.transmits(now: 0.0)
    @server_id = QUIC::Wire::Packet.parse(reply.first.payload, dcid_length: 8).header.scid
    reply.each { client.receive(_1.payload, from: SERVER, now: 0.0) }
    handshake(client, server)
    @number = 1000
    server
  end

  # The client's 1-RTT packet of `frames`, given to `server`.
  def send_frames(server, *frames)
    payload = QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3)
    server.receive(client_one_rtt(@keylog, dcid: @server_id, payload:, packet_number: @number += 1), from: CLIENT, now: 0.1)
  end

  def stream(stream_id, offset, data) = QUIC::Wire::Frame::Stream.new(stream_id:, offset:, data: data.b, fin: false)

  # Streams that never send their first bytes count to the connection's
  # limit as far as they go: of streams each sent a byte at the end of its
  # window, the second passes MAX_DATA (CVE-2026-75804).
  def test_streams_with_nothing_before
    server = connected_server
    window = QUIC::Config.new.initial_max_stream_data_bidi_remote
    send_frames(server, stream(0, window - 1, "x"))
    refute server.closing?
    send_frames(server, stream(4, window - 1, "x"))
    assert_equal QUIC::ErrorCode::FLOW_CONTROL_ERROR, server.close_reason&.code
  end

  # STREAM data that runs to the end of its packet, which a substring of
  # the packet would keep whole, is kept in a String of its own
  # (CVE-2026-54873).
  def test_stream_data_does_not_keep_the_packet
    server = connected_server
    send_frames(server, stream(0, 1, "x" * 1000))
    kept = server.instance_variable_get(:@streams).instance_variable_get(:@receivers).fetch(0).instance_variable_get(:@ranges)
    assert_equal ["x" * 1000], kept.map(&:data)
    refute ObjectSpace.dump(kept.first.data).include?('"shared":true'), "the STREAM data is shared"
  end

  # Counts how often a piece of data received is looked at. A prepended
  # module stays once the test is over, so it counts only for the thread of
  # this test, and writes nothing to a module: the workers of other tests
  # receive stream data in Ractors, where it could not.
  module Looks
    def offset
      looks = Thread.current[:raiha_next_chunk_looks]
      looks << 1 if looks
      super
    end
  end

  # STREAM frames in no order, each with a hole on both sides: each finds
  # its place among those before in a number of looks that grows with the
  # logarithm of their number, not with the number (CVE-2026-42772).
  def test_data_out_of_order
    QUIC::Streams::Receiver::Chunk.prepend(Looks)
    streams = QUIC::Streams.new(role: :client, config: QUIC::Config.new, events: [], now: 0.0)
    pieces = 4000
    most = (0...pieces).to_a.shuffle(random: Random.new(1)).map do |piece|
      looks = Thread.current[:raiha_next_chunk_looks] = []
      streams.receive_stream(stream(1, 2 * piece + 1, "x"), now: 0.0)
      looks.size
    end.max
    assert_operator most, :<=, 6 * Math.log2(pieces)
    assert_operator most, :>, 0, "nothing was looked at"
  ensure
    Thread.current[:raiha_next_chunk_looks] = nil
  end

  # A client opens unidirectional streams and resets them at once, given
  # room for more as they end: a server whose application takes its events
  # stays, and one whose application never does closes with INTERNAL_ERROR
  # once more than MAX_EVENTS wait.
  def test_events_not_taken
    [true, false].each do |taking|
      client = client_connection
      server = server_connection(config: QUIC::Config.new(initial_max_streams_uni: 100))
      now = handshake(client, server)
      server.each_event { nil }
      resets = 0
      60.times do
        break if client.draining?
        while (stream_id = client.open_stream(direction: :uni))
          client.stream_reset(stream_id, error_code: 1)
          resets += 1
        end
        client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now:) }
        server.each_event { nil } if taking
        server.transmits(now:).each { client.receive(_1.payload, from: SERVER, now:) }
        client.each_event { nil }
        now += 0.01
      end
      assert_operator resets, :>, QUIC::Connection::MAX_EVENTS
      assert_equal (taking ? :open : QUIC::ErrorCode::INTERNAL_ERROR), server.close_reason&.code || :open
    end
  end
end
