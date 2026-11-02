require "raiha/next/test_helper"
require "raiha/next/tls"

# The keys of session tickets: where each comes from, pinned against HKDF
# computed here by hand, and which a static set seals and opens with.
class RaihaNextTLSTicketKeysTest < Minitest::Test
  TicketKeys = Raiha::Next::TLS::TicketKeys
  SEED = (1..32).to_a.pack("C*")
  OTHER = (33..64).to_a.pack("C*")
  NOW = Time.at(1_800_000_000)

  # HKDF-Expand-Label with the prefix "raiha ": one block of HMAC-SHA256
  # over the HkdfLabel and the counter 1 is enough for 32 bytes.
  def expand(seed, label, length)
    full = "raiha #{label}"
    info = [length, full.bytesize].pack("nC") + full + "\x00".b
    OpenSSL::HMAC.digest("SHA256", seed, info + "\x01".b).byteslice(0, length)
  end

  def test_where_the_keys_come_from
    entry = TicketKeys.derive(SEED, nil)
    assert_equal expand(SEED, "ticket key", 32), entry.aead_key
    assert_equal expand(SEED, "ticket nonce", 32), entry.nonce_key
    assert_equal expand(SEED, "ticket id", 8), entry.key_id
    refute_equal entry.aead_key, entry.nonce_key
  end

  def test_static_keys_seal_with_the_current_and_open_with_all
    keys = TicketKeys.static(current: SEED, previous: [OTHER])
    current = TicketKeys.derive(SEED, nil)
    previous = TicketKeys.derive(OTHER, nil)
    assert_equal current, keys.sealing(NOW)
    assert_equal current, keys.opening(current.key_id, NOW)
    assert_equal previous, keys.opening(previous.key_id, NOW + 10 * 365 * 86_400)
    assert_nil keys.opening("\x00".b * 8, NOW)
    assert Ractor.shareable?(keys)
  end

  def test_what_static_keys_refuse
    assert_raises(ArgumentError) { TicketKeys.static(current: "\x00".b * 31) }
    assert_raises(ArgumentError) { TicketKeys.static(current: SEED, previous: [SEED]) }
    assert_raises(ArgumentError) { TicketKeys.static(current: SEED, previous: OTHER) }
  end

  def test_no_key_shows
    keys = TicketKeys.static(current: SEED)
    entry = keys.sealing(NOW)
    refute_includes keys.inspect, entry.aead_key.unpack1("H*")
    refute_includes entry.inspect, entry.aead_key.inspect
    assert_includes keys.inspect, entry.key_id.unpack1("H*")
  end
end

# Keys of a ratchet: every worker computes the same ones, seals with the
# current epoch's until past the horizon, and opens a ticket only within the
# epochs a ticket can live, one ahead for clocks that differ.
class RaihaNextTLSTicketKeysRatchetTest < Minitest::Test
  TicketKeys = Raiha::Next::TLS::TicketKeys
  BASE = (1..32).to_a.pack("C*")
  ORIGIN = Time.at(1_700_000_000)
  HOUR = 3600

  def ratchet(now, base: BASE, base_epoch: 0, **options)
    TicketKeys.ratchet(base:, base_epoch:, origin: ORIGIN, now:, **options).for_ticket_lifetime(7200)
  end

  # The seed of `epoch` from BASE at epoch 0, by hand.
  def seed(epoch)
    (0...epoch).inject(BASE) do |seed, _|
      info = [32, "raiha ticket ratchet".bytesize].pack("nC") + "raiha ticket ratchet" + "\x00".b
      OpenSSL::HMAC.digest("SHA256", seed, info + "\x01".b)
    end
  end

  def test_workers_compute_the_same_keys
    now = ORIGIN + 100 * HOUR + 5
    keys = ratchet(now)
    assert_equal TicketKeys.derive(seed(100), 100), keys.sealing(now)
    assert_equal keys.sealing(now), ratchet(now + 600).sealing(now)
    later = now + 2 * HOUR
    advanced = keys.advance(now: later)
    assert_equal ratchet(later).sealing(later), advanced.sealing(later)
    assert_equal keys.sealing(now), advanced.opening(keys.sealing(now).key_id, later)
    assert Ractor.shareable?(keys)
  end

  # Without retain, the ticket lifetime in epochs plus one; with too few, an
  # error.
  def test_how_long_keys_are_kept
    now = ORIGIN + 100 * HOUR
    keys = ratchet(now)
    assert_equal 3, keys.retain
    assert_equal 97, keys.base_epoch
    assert_equal seed(97), keys.base
    assert_raises(ArgumentError) { TicketKeys.ratchet(base: BASE, base_epoch: 0, origin: ORIGIN, now:, retain: 1).for_ticket_lifetime(7200) }
    assert_raises(Raiha::Next::TLS::UsageError) { TicketKeys.ratchet(base: BASE, base_epoch: 0, origin: ORIGIN, now:).sealing(now) }
  end

  def test_sealing_stops_past_the_horizon
    now = ORIGIN + 100 * HOUR
    keys = ratchet(now)
    assert_equal ORIGIN + 125 * HOUR, keys.issuing_until
    assert_equal ORIGIN + 101 * HOUR, keys.next_advance_at
    refute_nil keys.sealing(keys.issuing_until - 1)
    assert_nil keys.sealing(keys.issuing_until)
    refute_nil keys.advance(now: keys.issuing_until).sealing(keys.issuing_until)
  end

  # Keys built further back than a build can walk from, a server that took
  # no connection for over a year say, get there through builds in between.
  def test_advance_far_ahead
    now = ORIGIN + 100 * HOUR
    later = now + 10_000 * HOUR
    advanced = ratchet(now).advance(now: later)
    assert_equal TicketKeys.derive(seed(10_100), 10_100), advanced.sealing(later)
    assert_equal ORIGIN + 10_101 * HOUR, advanced.next_advance_at
  end

  def test_which_tickets_open
    now = ORIGIN + 100 * HOUR
    keys = ratchet(now)
    sealed = keys.sealing(now)
    assert_equal sealed, keys.opening(sealed.key_id, now + 3 * HOUR)
    assert_nil keys.opening(sealed.key_id, now + 4 * HOUR)
    ahead = keys.sealing(now + HOUR)
    assert_equal ahead, keys.opening(ahead.key_id, now)
    assert_nil keys.opening(keys.sealing(now + 2 * HOUR).key_id, now)
  end

  def test_what_a_ratchet_refuses
    now = ORIGIN + 100 * HOUR
    assert_raises(ArgumentError) { ratchet(now, horizon: 0) }
    assert_raises(ArgumentError) { ratchet(now, base_epoch: 98) }
    assert_raises(ArgumentError) { ratchet(ORIGIN + 5000 * HOUR) }
    assert_raises(ArgumentError) { ratchet(now, base: "\x00".b * 16) }
    assert_raises(ArgumentError) { ratchet(now, epoch: 0) }
  end

  def test_no_key_shows
    keys = ratchet(ORIGIN + 100 * HOUR)
    refute_includes keys.inspect, keys.base.unpack1("H*")
    refute_includes keys.inspect, keys.base.inspect
  end
end
