require "test_helper"
require "raiha/quic"
require "raiha/quic/test"

# RFC 9001 "Packet Protection": the keys of each encryption level.
class RaihaNextQUICPacketProtectionTest < Minitest::Test
  QUIC = Raiha::QUIC
  V = QUIC::Test::Vectors
  SUITE = Raiha::TLS::CipherSuite::TLS_AES_128_GCM_SHA256

  CLIENT_SECRET = "c".b * 32
  SERVER_SECRET = "s".b * 32

  def protection(role, &updated) = QUIC::PacketProtection.new(role:, version: QUIC::Version::V1, &updated)

  def seal(keys) = keys.aead.seal(packet_number: 0, header: "h".b, plaintext: "p".b)

  # A server with the 1-RTT keys of CLIENT_SECRET to read and SERVER_SECRET
  # to write.
  def one_rtt_server(&updated)
    protection(:server, &updated).tap do |server|
      server.install(:one_rtt, :write, secret: SERVER_SECRET, suite: SUITE)
      server.install(:one_rtt, :read, secret: CLIENT_SECRET, suite: SUITE)
    end
  end

  # The 1-RTT keys of `secret` after `phase` key updates.
  def keys_at(secret, phase)
    keys = QUIC::Crypto::Keys.derive(suite: SUITE, secret:, version: QUIC::Version::V1)
    phase.times do
      secret = QUIC::Crypto::Keys.next_secret(suite: SUITE, secret:, version: QUIC::Version::V1)
      keys = keys.update(suite: SUITE, secret:, version: QUIC::Version::V1)
    end
    keys
  end

  # Opens on `server` at `now` a 1-RTT packet numbered `number` sealed
  # with the client's keys of `phase`, its Key Phase bit `bit`, the PTO
  # period a second.
  def open_one_rtt(server, number, phase:, bit: phase & 1, now: 0.0)
    header = QUIC::Wire::ShortHeader.new(dcid: "".b, key_phase: bit)
    packet = QUIC::Wire::Packet.seal(header, packet_number: number, packet_number_length: 4, payload: "\x01".b * 20,
      keys: keys_at(CLIENT_SECRET, phase))
    unmasked = QUIC::Wire::Packet.parse(packet, dcid_length: 0).unmask(server.read_keys(:one_rtt).header_protection, largest: nil)
    server.open(:one_rtt, unmasked, now:, pto: 1.0)
  end

  # Each end writes with its own Initial keys and reads with the other's
  # (RFC 9001 appendix A.1).
  def test_initial
    client = protection(:client)
    server = protection(:server)
    refute client.can_write?(:initial)
    client.install_initial(V::Keys::DCID)
    server.install_initial(V::Keys::DCID)
    c = V::ClientInitial
    plaintext = c::FRAMES.ljust(c::PAYLOAD_LENGTH, "\0".b)
    assert_equal_bin c::PACKET.byteslice(c::HEADER.bytesize..),
      client.write_keys(:initial).aead.seal(packet_number: c::PACKET_NUMBER, header: c::HEADER, plaintext:)
    assert_equal seal(client.write_keys(:initial)), seal(server.read_keys(:initial))
    assert_equal seal(server.write_keys(:initial)), seal(client.read_keys(:initial))
  end

  def test_secrets_from_tls
    protection = protection(:client)
    secret = "s".b * 32
    protection.install(:handshake, :write, secret:, suite: SUITE)
    assert protection.can_write?(:handshake)
    refute protection.can_read?(:handshake)
    assert_equal seal(QUIC::Crypto::Keys.derive(suite: SUITE, secret:, version: QUIC::Version::V1)), seal(protection.write_keys(:handshake))
    assert_raises(ArgumentError) { protection.install(:initial, :read, secret:, suite: SUITE) }
  end

  # RFC 9001 "Responding to a Key Update": a packet that opens with the
  # next keys moves both directions to them, and the header protection
  # keys stay.
  def test_the_peer_updates_the_keys
    phases = []
    server = one_rtt_server { phases << _1 }
    hp = server.read_keys(:one_rtt).header_protection
    assert open_one_rtt(server, 1, phase: 0)
    assert_equal 0, server.key_phase_bit
    assert open_one_rtt(server, 2, phase: 1)
    assert_equal [1], phases
    assert_equal 1, server.key_phase
    assert_equal 1, server.key_phase_bit
    assert_equal seal(keys_at(SERVER_SECRET, 1)), seal(server.write_keys(:one_rtt))
    assert_same hp, server.read_keys(:one_rtt).header_protection
    server.sent(0, acknowledging: 2)
    assert open_one_rtt(server, 3, phase: 2)
    assert_equal [1, 2], phases
  end

  # RFC 9001 "Receiving with Different Keys": with the bit of the previous
  # phase, a packet numbered below those of the current phase opens with
  # the previous keys, one above with the next.
  def test_delayed_packets_open_with_the_previous_keys
    server = one_rtt_server
    open_one_rtt(server, 10, phase: 1)
    assert open_one_rtt(server, 5, phase: 0)
    assert_nil open_one_rtt(server, 11, phase: 0)
    assert_equal 1, server.key_phase
    server.sent(0, acknowledging: 10)
    assert open_one_rtt(server, 12, phase: 2)
    assert_equal 2, server.key_phase
  end

  # RFC 9001 "Receiving with Different Keys": the previous keys go three
  # PTOs after the first packet opens with the new ones.
  def test_the_previous_keys_go_three_ptos_later
    server = one_rtt_server
    assert_nil server.next_timeout
    open_one_rtt(server, 10, phase: 1, now: 1.0)
    assert_equal 4.0, server.next_timeout
    assert open_one_rtt(server, 5, phase: 0, now: 3.9)
    server.handle_timeout(now: 4.0)
    assert_nil server.next_timeout
    assert_nil open_one_rtt(server, 6, phase: 0, now: 4.0)
  end

  # A packet that comes after the deadline does not open with the previous
  # keys, whether the timeout has been handled or not.
  def test_the_previous_keys_are_gone_at_the_deadline
    server = one_rtt_server
    open_one_rtt(server, 10, phase: 1, now: 1.0)
    assert_nil open_one_rtt(server, 5, phase: 0, now: 4.0)
  end

  # A confirmed server that has opened the client's packet 0 and had its
  # own packet 0 acknowledged.
  def confirmed_server(&updated)
    one_rtt_server(&updated).tap do |server|
      server.handshake_confirmed!
      open_one_rtt(server, 0, phase: 0)
      server.sent(0)
      server.acknowledged(0)
    end
  end

  # quic-go's interval: the first update comes after 100 packets sent or
  # opened with the first keys.
  def test_the_first_update_after_100_packets
    phases = []
    server = confirmed_server { phases << _1 }
    98.times { server.sent(_1 + 1) }
    server.update_keys_if_due
    assert_equal 0, server.key_phase
    server.sent(99)
    server.update_keys_if_due
    assert_equal [1], phases
    assert_equal seal(keys_at(SERVER_SECRET, 1)), seal(server.write_keys(:one_rtt))
    assert open_one_rtt(server, 1, phase: 1)
  end

  def test_packets_opened_count_too
    server = confirmed_server
    99.times { open_one_rtt(server, _1 + 1, phase: 0) }
    server.update_keys_if_due
    assert_equal 1, server.key_phase
  end

  # quic-go's interval: every later update comes after 100,000 packets.
  def test_later_updates_after_100000_packets
    server = confirmed_server
    99.times { server.sent(_1 + 1) }
    server.update_keys_if_due
    open_one_rtt(server, 1, phase: 1)
    server.sent(100)
    server.acknowledged(100)
    99_998.times { server.sent(_1 + 101) }
    server.update_keys_if_due
    assert_equal 1, server.key_phase
    server.sent(100_099)
    server.update_keys_if_due
    assert_equal 2, server.key_phase
  end

  # RFC 9001 "Initiating a Key Update": not before the handshake is
  # confirmed.
  def test_no_update_before_confirmation
    server = one_rtt_server
    open_one_rtt(server, 0, phase: 0)
    server.sent(0)
    server.acknowledged(0)
    200.times { server.sent(_1 + 1) }
    server.update_keys_if_due
    assert_equal 0, server.key_phase
    server.handshake_confirmed!
    server.update_keys_if_due
    assert_equal 1, server.key_phase
  end

  # RFC 9001 "Initiating a Key Update": not before a packet sent with the
  # current keys is acknowledged.
  def test_no_update_before_an_ack_of_the_current_keys
    server = one_rtt_server
    server.handshake_confirmed!
    open_one_rtt(server, 0, phase: 0)
    server.acknowledged(4)
    200.times { server.sent(_1 + 5) }
    server.update_keys_if_due
    assert_equal 0, server.key_phase
    server.acknowledged(5)
    server.update_keys_if_due
    assert_equal 1, server.key_phase
  end

  def assert_key_update_error(&)
    error = assert_raises(QUIC::Violation, &)
    assert_equal QUIC::ErrorCode::KEY_UPDATE_ERROR, error.code
  end

  # RFC 9001 "Responding to a Key Update": the peer may update again only
  # once this end has acknowledged, with the current keys, a packet of the
  # peer's current keys.
  def test_an_update_again_before_an_ack
    server = one_rtt_server
    open_one_rtt(server, 10, phase: 1)
    server.sent(0, acknowledging: 9)
    assert_key_update_error { open_one_rtt(server, 11, phase: 2) }
  end

  def test_an_update_again_after_an_ack
    server = one_rtt_server
    open_one_rtt(server, 10, phase: 1)
    server.sent(0, acknowledging: 10)
    assert open_one_rtt(server, 11, phase: 2)
    assert_equal 2, server.key_phase
  end

  # RFC 9001 "Responding to a Key Update": an ACK of a packet of the new
  # keys that comes before any packet of them is the peer not following
  # the update.
  def test_an_ack_with_older_keys
    server = confirmed_server
    99.times { server.sent(_1 + 1) }
    server.update_keys_if_due
    server.sent(100)
    server.acknowledged(99)
    assert_key_update_error { server.acknowledged(100) }
  end

  def test_an_ack_after_a_packet_of_the_new_keys
    server = confirmed_server
    99.times { server.sent(_1 + 1) }
    server.update_keys_if_due
    server.sent(100)
    open_one_rtt(server, 1, phase: 1)
    server.acknowledged(100)
    server.sent(101)
    server.acknowledged(101)
  end

  # RFC 9001 "Sending with Updated Keys": a packet with a higher number
  # than one of newer keys is an error, whichever comes first.
  def test_the_next_keys_on_a_lower_number
    server = one_rtt_server
    open_one_rtt(server, 5, phase: 0)
    open_one_rtt(server, 11, phase: 0)
    assert_key_update_error { open_one_rtt(server, 10, phase: 1) }
  end

  def test_the_previous_keys_on_a_higher_number
    server = one_rtt_server
    open_one_rtt(server, 7, phase: 1)
    open_one_rtt(server, 6, phase: 0)
    assert_key_update_error { open_one_rtt(server, 5, phase: 1) }
  end

  # RFC 9001 "Limits on AEAD Usage": packets that fail authentication are
  # counted across all keys, and one more than the integrity limit is
  # AEAD_LIMIT_REACHED.
  def test_the_integrity_limit
    limits = { quic: Raiha::TLS::CipherSuite::Limits.new(confidentiality: nil, integrity: 2) }
    suite = SUITE.with(limits:)
    server = protection(:server)
    server.install(:handshake, :read, secret: CLIENT_SECRET, suite:)
    server.install(:one_rtt, :read, secret: CLIENT_SECRET, suite:)
    header = QUIC::Wire::LongHeader.new(type: :handshake, version: QUIC::Version::V1, dcid: "".b, scid: "".b)
    forged = QUIC::Wire::Packet.seal(header, packet_number: 0, packet_number_length: 4, payload: "\x01".b * 20, keys: keys_at(SERVER_SECRET, 0))
    unmasked = QUIC::Wire::Packet.parse(forged, dcid_length: 0).unmask(server.read_keys(:handshake).header_protection, largest: nil)
    assert_nil server.open(:handshake, unmasked, now: 0.0, pto: 1.0)
    assert_nil open_one_rtt(server, 1, phase: 1, bit: 0)
    assert open_one_rtt(server, 2, phase: 0)
    error = assert_raises(QUIC::Violation) { open_one_rtt(server, 3, phase: 0, bit: 1) }
    assert_equal QUIC::ErrorCode::AEAD_LIMIT_REACHED, error.code
  end

  # A server whose 1-RTT keys are of a suite that allows 3 packets per key,
  # its handshake confirmed and a packet of the client opened.
  def limited_server
    limits = { quic: Raiha::TLS::CipherSuite::Limits.new(confidentiality: 3, integrity: nil) }
    suite = SUITE.with(limits:)
    protection(:server).tap do |server|
      server.install(:one_rtt, :write, secret: SERVER_SECRET, suite:)
      server.install(:one_rtt, :read, secret: CLIENT_SECRET, suite:)
      server.handshake_confirmed!
      open_one_rtt(server, 0, phase: 0)
    end
  end

  # RFC 9001 "Limits on AEAD Usage": the keys update before they protect
  # more packets than the confidentiality limit, whatever the interval.
  def test_an_update_before_the_confidentiality_limit
    server = limited_server
    server.sent(0)
    server.acknowledged(0)
    server.sent(1)
    server.update_keys_if_due
    assert_equal 1, server.key_phase
  end

  # RFC 9001 "Limits on AEAD Usage": keys that cannot be updated close the
  # connection with AEAD_LIMIT_REACHED while one packet is left for the
  # CONNECTION_CLOSE, and are not used after it.
  def test_the_confidentiality_limit
    server = limited_server
    server.sent(0)
    server.update_keys_if_due
    server.sent(1)
    error = assert_raises(QUIC::Violation) { server.update_keys_if_due }
    assert_equal QUIC::ErrorCode::AEAD_LIMIT_REACHED, error.code
    assert server.can_write?(:one_rtt)
    server.sent(2)
    refute server.can_write?(:one_rtt)
  end

  # A Key Phase bit changed on a packet that does not open with the next
  # keys changes nothing.
  def test_a_changed_bit_alone_updates_nothing
    server = one_rtt_server
    assert_nil open_one_rtt(server, 1, phase: 0, bit: 1)
    assert_equal 0, server.key_phase
    assert open_one_rtt(server, 2, phase: 0)
  end

  # A level discarded stays so.
  def test_discard
    protection = protection(:client)
    protection.install_initial(V::Keys::DCID)
    protection.discard(:initial)
    refute protection.can_read?(:initial)
    refute protection.can_write?(:initial)
    assert protection.discarded?(:initial)
    protection.install(:handshake, :read, secret: "s".b * 32, suite: SUITE)
    protection.discard(:handshake)
    assert_raises(ArgumentError) { protection.install(:handshake, :read, secret: "s".b * 32, suite: SUITE) }
  end
end
