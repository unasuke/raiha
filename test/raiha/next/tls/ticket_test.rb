require "raiha/next/test_helper"
require "raiha/next/tls"

# Sealing a session ticket and opening it again: what it holds comes back,
# and a ticket of another binding, key or version, a forged one and one of
# a size out of range do not open, each for its own reason.
class RaihaNextTLSTicketTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Ticket = TLS::Ticket
  NOW = Time.at(1_800_000_000)
  KEYS = TLS::TicketKeys.static(current: "\x01".b * 32)
  CONFIG_PART = Ticket.config_binding(profile: TLS::Profile::TCP, resumption_scope: "")
  BINDING = Ticket.binding(CONFIG_PART, resumption_binding: "", server_name: "example.com", alpn: "h2")

  def plaintext(**changes)
    Ticket::Plaintext.new(issued_at: 1_800_000_000_123, authenticated_at: 1_799_999_000_000, lifetime: 7200,
      age_add: 0xdeadbeef, cipher_suite: 0x1301, psk: "\x02".b * 32, alpn: "h2", early_data_allowed: true, client: nil,
      early_data_context: "context").with(**changes)
  end

  def seal(text = plaintext, keys: KEYS, binding: BINDING, random: "\x03".b * 16)
    Ticket.seal(text, entry: keys.sealing(NOW), binding:, random:)
  end

  def open(ticket, keys: KEYS, binding: BINDING, max_size: 8192) = Ticket.open(ticket, keys:, binding:, now: NOW, max_size:)

  def test_what_a_ticket_holds_comes_back
    assert_equal plaintext, open(seal)
    client = Ticket::ClientCertificate.new(leaf: "leaf".b, rules_digest: "\x04".b * 32, anchor_digest: "\x05".b * 32,
      valid_from: 1_700_000_000, valid_until: 1_900_000_000, verified: true)
    assert_equal plaintext(client:, early_data_allowed: false), open(seal(plaintext(client:, early_data_allowed: false)))
  end

  # The plaintext is padded to a multiple of 64 bytes, so a ticket is 37
  # bytes more than that.
  def test_the_size_of_a_ticket
    assert_equal 0, (seal.bytesize - Ticket::OVERHEAD) % 64
    assert_equal seal.bytesize, seal(plaintext(alpn: "h3", early_data_context: "longer context")).bytesize
  end

  # The nonce is of the random bytes, the AAD and the plaintext: the same
  # three give the same ticket, a change of any gives another nonce.
  def test_the_nonce
    assert_equal seal, seal
    nonce = ->(ticket) { ticket.byteslice(9, 12) }
    refute_equal nonce.(seal), nonce.(seal(random: "\x04".b * 16))
    refute_equal nonce.(seal), nonce.(seal(plaintext(age_add: 1)))
  end

  def test_tickets_that_do_not_open
    ticket = seal
    assert_equal :malformed, open(ticket.byteslice(0, 36))
    assert_equal :malformed, open(ticket, max_size: ticket.bytesize - 1)
    assert_equal :unknown_version, open("\x02".b + ticket.byteslice(1..))
    assert_equal :unknown_key, open(ticket, keys: TLS::TicketKeys.static(current: "\x09".b * 32))
    forged = ticket.dup
    forged.setbyte(40, forged.getbyte(40) ^ 1)
    assert_equal :aead_failure, open(forged)
    other_name = Ticket.binding(CONFIG_PART, resumption_binding: "", server_name: "other.example", alpn: "h2")
    assert_equal :aead_failure, open(ticket, binding: other_name)
    other_alpn = Ticket.binding(CONFIG_PART, resumption_binding: "", server_name: "example.com", alpn: "h3")
    assert_equal :aead_failure, open(ticket, binding: other_alpn)
    quic = Ticket.binding(Ticket.config_binding(profile: TLS::Profile::QUIC, resumption_scope: ""), resumption_binding: "",
      server_name: "example.com", alpn: "h2")
    assert_equal :aead_failure, open(ticket, binding: quic)
  end

  # Padding that is not all zeros is refused even under the right key.
  def test_padding_must_be_zeros
    entry = KEYS.sealing(NOW)
    padded = plaintext.encode
    padded.setbyte(padded.bytesize - 1, 1)
    header = "\x01".b + entry.key_id
    nonce = "\x00".b * 12
    sealed = TLS::Crypto::AEAD.new(:aes_256_gcm, entry.aead_key).seal(nonce:, aad: header + BINDING, plaintext: padded)
    assert_equal :malformed, open(header + nonce + sealed)
  end

  def test_the_psk_does_not_show
    refute_includes plaintext.inspect, plaintext.psk.inspect
  end

  # The server clears an opened ticket's PSK once it is done with it.
  def test_the_psk_of_an_opened_ticket_can_be_forgotten
    psk = open(seal).psk
    psk.clear
    assert_empty psk
  end
end
