require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# KeyUpdate after a TCP handshake.
class RaihaNextTLSKeyUpdateHandlingTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Pair = NextTLSPair
  NOW = Pair::NOW
  KeyUpdate = TLS::Handshake::KeyUpdate
  REQUESTED = KeyUpdate.new(request_update: KeyUpdate::UPDATE_REQUESTED).encode
  NOT_REQUESTED = KeyUpdate.new(request_update: KeyUpdate::UPDATE_NOT_REQUESTED).encode

  def connected = Pair.run(Pair.client)

  def failure(machine) = machine.each_event.grep(TLS::Event::Failed).first

  # RFC 9846: a KeyUpdate changes keys, so it ends its record. Each
  # `receive` over TCP is one record, and nothing is answered.
  def test_a_key_update_must_end_its_record
    [REQUESTED + NOT_REQUESTED, REQUESTED + REQUESTED.byteslice(0, 2)].each do |bytes|
      machine = connected.client
      machine.receive(bytes, epoch: :application, now: NOW)
      assert_equal TLS::Event::Failed.new(alert: :unexpected_message, reason: :handshake_data_spans_key_change), failure(machine)
      assert_equal [[:alert, :application, :unexpected_message]], Pair.shape(machine.outputs)
    end
    # Split across records is fine as long as it ends one.
    machine = connected.client
    REQUESTED.each_char { |byte| machine.receive(byte, epoch: :application, now: NOW) }
    refute machine.failed?
  end
end
