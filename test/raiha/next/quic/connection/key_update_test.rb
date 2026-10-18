require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9001 "Key Update", with the client's packets made from its key log
# once the handshake is done.
class RaihaNextQUICConnectionKeyUpdateTest < Minitest::Test
  include NextQUICPair

  PING = "\x01".b

  def events(connection) = [].tap { |events| connection.each_event { events << _1 } }

  # A server done with the handshake, the client's key log, the server's
  # connection ID and the time.
  def connected
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection
    server.receive(client.transmits(now: 0.0).first.payload, from: CLIENT, now: 0.0)
    reply = server.transmits(now: 0.0)
    server_id = QUIC::Wire::Packet.parse(reply.first.payload, dcid_length: 8).header.scid
    reply.each { client.receive(_1.payload, from: SERVER, now: 0.0) }
    now = handshake(client, server)
    events(server)
    [server, keylog, server_id, now]
  end

  # RFC 9001 "Responding to a Key Update": the server follows the client's
  # update and acknowledges the packet that started it with its new keys.
  def test_the_server_follows_a_key_update
    server, keylog, server_id, now = connected
    server.receive(client_one_rtt(keylog, dcid: server_id, payload: PING, phase: 1), from: CLIENT, now:)
    assert_equal [QUIC::Event::KeyUpdated.new(phase: 1)], events(server).grep(QUIC::Event::KeyUpdated)
    opened = server.transmits(now: now + 1.0).map { server_one_rtt(keylog, _1.payload, phase: 1) }
    refute_empty opened
    assert opened.all? { |bit, _, _| bit == 1 }, opened.inspect
    assert opened.flat_map(&:last).grep(QUIC::Wire::Frame::Ack).any? { _1.largest == 1000 }
  end

  # RFC 9001 "Receiving with Different Keys": a packet of the previous key
  # phase opens until three PTOs after the update, and not after.
  def test_the_previous_keys_go_three_ptos_after_the_update
    server, keylog, server_id, now = connected
    server.receive(client_one_rtt(keylog, dcid: server_id, payload: PING, packet_number: 1000, phase: 1), from: CLIENT, now:)
    deadline = now + 3 * server.path.rtt.pto_period
    server.receive(client_one_rtt(keylog, dcid: server_id, payload: PING, packet_number: 998), from: CLIENT, now: deadline - 0.001)
    server.handle_timeout(now: deadline)
    server.receive(client_one_rtt(keylog, dcid: server_id, payload: PING, packet_number: 999), from: CLIENT, now: deadline)
    opened = server.transmits(now: deadline + 1.0).filter_map { server_one_rtt(keylog, _1.payload, phase: 1) }
    acked = opened.flat_map(&:last).grep(QUIC::Wire::Frame::Ack).flat_map(&:ranges)
    assert acked.any? { _1.cover?(998) }, acked.inspect
    refute acked.any? { _1.cover?(999) }, acked.inspect
  end

  # A payload of an ACK of the server's packet `largest` and a PING.
  def ack_of(largest)
    ack = QUIC::Wire::Frame::Ack.new(ranges: [largest..largest], delay: 0)
    QUIC::Wire::Frame.encode([ack, QUIC::Wire::Frame::Ping.new], ack_delay_exponent: 3)
  end

  # The server once it has updated its keys on its own, quic-go's interval
  # after a packet of its first keys was acknowledged; with the client's
  # key log, the server's connection ID, the time, and what the server
  # sent after, opened with its new keys.
  def updated_by_server
    server, keylog, server_id, now = connected
    server.transmits(now:)
    100.times { server.receive(client_one_rtt(keylog, dcid: server_id, payload: PING, packet_number: 1000 + _1), from: CLIENT, now:) }
    first = server.transmits(now:).map { server_one_rtt(keylog, _1.payload, phase: 0) }
    refute_empty first
    assert first.all?, "the server keeps its first keys until a packet of them is acknowledged"
    server.receive(client_one_rtt(keylog, dcid: server_id, payload: ack_of(first.map { _2 }.max), packet_number: 1100), from: CLIENT, now:)
    [server, keylog, server_id, now, server.transmits(now: now + 1.0).map { server_one_rtt(keylog, _1.payload, phase: 1) }]
  end

  def test_the_server_updates_its_keys
    server, _, _, _, updated = updated_by_server
    refute_empty updated
    assert updated.all? { |bit, _, _| bit == 1 }, updated.inspect
    assert_equal [QUIC::Event::KeyUpdated.new(phase: 1)], events(server).grep(QUIC::Event::KeyUpdated)
  end

  # RFC 9001 "Responding to a Key Update": the client acknowledges, with
  # its old keys, a packet of the server's new keys: KEY_UPDATE_ERROR.
  def test_an_ack_with_older_keys_closes
    server, keylog, server_id, now, updated = updated_by_server
    largest = updated.map { _2 }.max
    server.receive(client_one_rtt(keylog, dcid: server_id, payload: ack_of(largest), packet_number: 1101), from: CLIENT, now:)
    assert server.closing?
    assert_equal QUIC::ErrorCode::KEY_UPDATE_ERROR, server.close_reason.code
  end

  # RFC 9001 "Responding to a Key Update": the client updates again before
  # the server has acknowledged a packet of its new keys: KEY_UPDATE_ERROR.
  def test_an_update_again_before_an_ack_closes
    server, keylog, server_id, now = connected
    server.receive(client_one_rtt(keylog, dcid: server_id, payload: PING, packet_number: 1000, phase: 1), from: CLIENT, now:)
    server.receive(client_one_rtt(keylog, dcid: server_id, payload: PING, packet_number: 1001, phase: 2), from: CLIENT, now:)
    assert server.closing?
    assert_equal QUIC::ErrorCode::KEY_UPDATE_ERROR, server.close_reason.code
  end

  # Once the server has sent its ACK with the new keys, the client may
  # update again.
  def test_an_update_again_after_an_ack
    server, keylog, server_id, now = connected
    server.receive(client_one_rtt(keylog, dcid: server_id, payload: PING, packet_number: 1000, phase: 1), from: CLIENT, now:)
    server.transmits(now: now + 1.0)
    server.receive(client_one_rtt(keylog, dcid: server_id, payload: PING, packet_number: 1001, phase: 2), from: CLIENT, now: now + 1.0)
    refute server.closing?
    assert_equal [1, 2], events(server).grep(QUIC::Event::KeyUpdated).map(&:phase)
  end
end
