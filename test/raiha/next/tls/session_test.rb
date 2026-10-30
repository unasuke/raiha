require "raiha/next/test_helper"
require "raiha/next/tls"

# A session a client keeps: into plain values and back, whether it is still
# usable, the PSK and the ticket age it gives, and a store that hands each
# out once.
class RaihaNextTLSSessionTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Session = TLS::Session
  NOW = Time.at(1_800_000_000)
  NOW_MS = 1_800_000_000_000

  def session(**changes)
    Session.new(ticket: "ticket".b, ticket_nonce: "\x00\x01".b, resumption_secret: "\x07".b * 32, cipher_suite: 0x1301,
      issued_at: NOW_MS, lifetime: 7200, age_add: 0xffff_fff0, max_early_data_size: 0, server_name: "example.com",
      alpn: "h2", peer_certificates: ["der".b], authenticated_at: NOW_MS - 1000).with(**changes)
  end

  def test_into_plain_values_and_back
    assert_equal session, Session.from_h(session.to_h)
    assert_equal session(server_name: nil, alpn: nil), Session.from_h(session(server_name: nil, alpn: nil).to_h)
    assert_raises(ArgumentError) { Session.from_h(session.to_h.except(:ticket)) }
    assert_raises(ArgumentError) { Session.from_h(session.to_h.merge(issued_at: "0")) }
    assert_raises(ArgumentError) { Session.from_h(session.to_h.merge(cipher_suite: 0x9999)) }
  end

  # The ticket's lifetime, at most 7 days, and 7 days from the full
  # handshake.
  def test_usable
    assert session.usable?(now: NOW + 7200)
    refute session.usable?(now: NOW + 7200.001)
    long = session(lifetime: 1_000_000)
    assert long.usable?(now: NOW + 604_799)
    refute long.usable?(now: NOW + 604_801)
    refute session(authenticated_at: NOW_MS - 604_000_000).usable?(now: NOW + 1000)
  end

  # RFC 9846: PSK = HKDF-Expand-Label(resumption_secret, "resumption",
  # ticket_nonce, Hash.length); the age is milliseconds plus age_add.
  def test_the_psk_and_the_age
    expected = TLS::KeySchedule.expand_label(secret: "\x07".b * 32, label: "resumption", context: "\x00\x01".b, length: 32, hash: :sha256)
    assert_equal expected, session.psk
    assert_equal 48, session(cipher_suite: 0x1302).psk.bytesize
    # age_add is 2^32 - 16.
    assert_equal 1500 - 16, session.obfuscated_ticket_age(NOW + 1.5)
  end

  def test_the_secret_does_not_show
    refute_includes session.inspect, session.resumption_secret.inspect
  end

  def test_a_store_hands_each_session_out_once
    store = TLS::SessionStore::Memory.new
    older = session(ticket: "older".b)
    newer = session(ticket: "newer".b)
    store.put(older).put(newer).put(session(server_name: "other.example"))
    assert_equal newer, store.take("example.com", now: NOW)
    assert_equal older, store.take("example.com", now: NOW)
    assert_nil store.take("example.com", now: NOW)
    store.put(session)
    assert_nil store.take("example.com", now: NOW + 7201)
  end

  def test_a_store_keeps_eight_a_server
    store = TLS::SessionStore::Memory.new
    10.times { |i| store.put(session(ticket: "t#{i}".b)) }
    taken = Array.new(9) { store.take("example.com", now: NOW)&.ticket }
    assert_equal (2..9).map { "t#{_1}".b }.reverse + [nil], taken
  end
end
