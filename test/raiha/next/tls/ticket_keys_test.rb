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
