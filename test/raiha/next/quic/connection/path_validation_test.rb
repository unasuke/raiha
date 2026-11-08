require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9000 "Path Validation", on a server a client probes from a new
# address: the probe is answered on that path, with an ID of the client's
# no path sent with.
class RaihaNextQUICConnectionPathValidationTest < Minitest::Test
  include NextQUICPair

  NEW = ["198.51.100.7", 61_000].freeze

  # A server done with the handshake, its connection ID "s" * 8, given
  # `ids` more IDs of the client's, "c0000001" on; the client's key log;
  # and the time.
  def connected(ids: 3, config: QUIC::Config.new)
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection(source_connection_id: "s".b * 8, config:)
    now = handshake(client, server)
    server.each_event { nil }
    issued = (1..ids).map do |sequence_number|
      QUIC::Wire::Frame::NewConnectionID.new(sequence_number:, retire_prior_to: 0, connection_id: format("c%07d", sequence_number).b,
        stateless_reset_token: format("%016d", sequence_number).b)
    end
    issued.each_slice(30).with_index { |frames, index| server.receive(packet(keylog, *frames, number: 900 + index), from: CLIENT, now:) }
    server.transmits(now:)
    [server, keylog, now]
  end

  # A client's 1-RTT packet to "s" * 8 with `frames`.
  def packet(keylog, *frames, number:)
    client_one_rtt(keylog, dcid: "s".b * 8, payload: QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3), packet_number: number)
  end

  def challenge(data) = QUIC::Wire::Frame::PathChallenge.new(data:)

  # Each of the server's datagrams at `now` as its destination, size,
  # Destination Connection ID and frames, PADDING left out.
  def sent(server, keylog, now)
    server.transmits(now:).map do |transmit|
      dcid = QUIC::Wire::Packet.parse(transmit.payload, dcid_length: 8).header.dcid
      frames = server_one_rtt(keylog, transmit.payload, phase: 0)&.last || []
      [transmit.destination, transmit.payload.bytesize, dcid, frames.reject { _1.is_a?(QUIC::Wire::Frame::Padding) }]
    end
  end

  def on(path, datagrams) = datagrams.select { _1.first == path }

  # A probe from a new address is answered on that path, with the
  # client's lowest ID no path sent with, as large as three times what
  # came on the path lets it.
  def test_a_probe_is_answered_on_its_path
    server, keylog, now = connected
    probe = packet(keylog, challenge("abcdefgh".b), number: 1000)
    server.receive(probe, from: NEW, to: SERVER, now:)
    (destination, size, dcid, frames), *rest = on(NEW, sent(server, keylog, now))
    assert_equal [NEW, "c0000001"], [destination, dcid]
    assert_equal [QUIC::Wire::Frame::PathResponse.new(data: "abcdefgh".b)], frames.grep(QUIC::Wire::Frame::PathResponse)
    assert_equal [3 * probe.bytesize, QUIC::Connection::MIN_INITIAL_DATAGRAM].min, size
    assert_empty rest
  end

  # With no ID of the client's left that no path sent with, a probe from
  # a new address goes unanswered.
  def test_no_id_to_answer_with
    server, keylog, now = connected(ids: 0)
    server.receive(packet(keylog, challenge("abcdefgh".b), number: 1000), from: NEW, to: SERVER, now:)
    assert_empty on(NEW, sent(server, keylog, now))
  end

  # Probes from a thousand addresses leave the server with three paths
  # besides the one in use, the newest, each the older's going as a newer
  # comes (CVE-2026-12707).
  def test_probes_from_a_thousand_addresses
    server, keylog, now = connected(ids: 1000, config: QUIC::Config.new(active_connection_id_limit: 1001))
    (1..1000).each do |i|
      server.receive(packet(keylog, challenge([i].pack("Q>")), number: 2000 + i), from: ["203.0.113.1", 10_000 + i], to: SERVER, now:)
    end
    destinations = sent(server, keylog, now).map(&:first).uniq - [CLIENT]
    assert_equal [10_998, 10_999, 11_000], destinations.map(&:last).sort
  end
end
