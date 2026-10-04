require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

# KeyUpdate after a TCP handshake: answered once, right before our next
# application data, and limited to a run of 32 without application data.
class RaihaNextTLSKeyUpdateHandlingTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Pair = NextTLSPair
  NOW = Pair::NOW
  KeyUpdate = TLS::Handshake::KeyUpdate
  REQUESTED = KeyUpdate.new(request_update: KeyUpdate::UPDATE_REQUESTED).encode
  NOT_REQUESTED = KeyUpdate.new(request_update: KeyUpdate::UPDATE_NOT_REQUESTED).encode

  def connected = Pair.run(Pair.client)

  def quic_pair
    tp = TLS::Extension::Opaque
    client = Pair.client(config: Pair.client_config(profile: TLS::Profile::QUIC, alpn: ["h3"]), extensions: [tp.new(type: 0x39, data: "c".b)])
    pair = Pair.run(client, { config: Pair.server_config(profile: TLS::Profile::QUIC, alpn: ["h3"]), extensions: [tp.new(type: 0x39, data: "s".b)] })
    assert pair.client.complete?
    pair
  end

  def failure(machine) = machine.each_event.grep(TLS::Event::Failed).first

  def request_updates(outputs)
    outputs.grep(TLS::Output::Message).map { |m| TLS::Handshake.parse(m.bytes, registry: TLS::Extension::Registry::BUILTIN).request_update }
  end

  # Answered once, right before our next application data.
  def test_many_requests_are_answered_once
    [:client, :server].each do |role|
      machine = connected.public_send(role)
      5.times { machine.receive(REQUESTED, epoch: :application, now: NOW) }
      assert_equal [[:secret, :application, :read]] * 5, Pair.shape(machine.outputs)
      machine.before_application_data
      outputs = machine.outputs
      assert_equal [[:message, :application, 24], [:secret, :application, :write]], Pair.shape(outputs), role
      assert_equal [KeyUpdate::UPDATE_NOT_REQUESTED], request_updates(outputs)
      machine.before_application_data
      assert_empty machine.outputs
      assert_equal 1, machine.key_update_epoch
    end
  end

  # Without application data of our own, nothing goes out at all.
  def test_nothing_is_sent_without_application_data
    machine = connected.client
    machine.receive(REQUESTED, epoch: :application, now: NOW)
    machine.receive(NOT_REQUESTED, epoch: :application, now: NOW)
    assert_equal 0, Pair.shape(machine.outputs).count { |shape| shape.first == :message }
  end

  # The secret we read with after the peer's KeyUpdate is the one it writes
  # with, and the same the other way after our answer.
  def test_the_next_secrets_match
    pair = connected
    pair.client.receive(REQUESTED, epoch: :application, now: NOW)
    pair.client.before_application_data
    client_outputs = pair.client.outputs
    Pair.deliver(client_outputs, pair.server)
    assert_equal client_outputs.grep(TLS::Output::Secret).last.secret, pair.server.outputs.grep(TLS::Output::Secret).last.secret
    refute pair.server.failed?
  end

  def test_before_application_data_does_nothing_until_complete_or_after_failure
    client = Pair.client
    client.outputs
    assert_nil client.before_application_data
    assert_empty client.outputs
    failed = connected.client
    failed.receive(REQUESTED, epoch: :application, now: NOW)
    failed.discard
    failed.before_application_data
    assert_equal [[:secret, :application, :read]], Pair.shape(failed.outputs)
  end

  # Past the limit RFC 9846 sets on senders, a request is not answered.
  def test_no_answer_past_the_sending_limit
    machine = connected.client
    side = machine.instance_variable_get(:@conductor).side
    side.instance_variable_set(:@key_updates, TLS::Handshake::KeyUpdateHandling::MAX_KEY_UPDATES)
    machine.receive(REQUESTED, epoch: :application, now: NOW)
    machine.before_application_data
    machine.request_key_update
    assert_equal [[:secret, :application, :read]], Pair.shape(machine.outputs)
  end

  # Each side's secrets follow the other's through updates both ways.
  def test_both_sides_stay_in_step
    pair = connected
    3.times do
      pair.client.request_key_update(request_peer_update: true)
      Pair.deliver(pair.client.outputs, pair.server)
      pair.server.before_application_data
      Pair.deliver(pair.server.outputs, pair.client)
    end
    assert_equal [3, 3], [pair.client.key_update_epoch, pair.server.key_update_epoch]
    refute pair.client.failed? || pair.server.failed?
  end

  # A KeyUpdate we owe goes before our own, and stands for one that does
  # not ask for the peer's.
  def test_request_key_update_with_an_owed_answer
    machine = connected.client
    machine.receive(REQUESTED, epoch: :application, now: NOW)
    machine.outputs
    machine.request_key_update(request_peer_update: false)
    assert_equal [KeyUpdate::UPDATE_NOT_REQUESTED], request_updates(machine.outputs)
    machine.receive(REQUESTED, epoch: :application, now: NOW)
    machine.outputs
    machine.request_key_update(request_peer_update: true)
    assert_equal [KeyUpdate::UPDATE_NOT_REQUESTED, KeyUpdate::UPDATE_REQUESTED], request_updates(machine.outputs)
  end

  # Until the peer's KeyUpdate arrives, another request cannot ask again.
  def test_one_request_at_a_time
    machine = connected.client
    machine.request_key_update(request_peer_update: true)
    machine.request_key_update(request_peer_update: true)
    assert_equal [KeyUpdate::UPDATE_REQUESTED, KeyUpdate::UPDATE_NOT_REQUESTED], request_updates(machine.outputs)
    machine.receive(NOT_REQUESTED, epoch: :application, now: NOW)
    machine.request_key_update(request_peer_update: true)
    assert_equal [KeyUpdate::UPDATE_REQUESTED], request_updates(machine.outputs)
  end

  def test_request_key_update_misuse
    assert_raises(TLS::UsageError) { Pair.client.request_key_update }
    assert_raises(TLS::UsageError) { quic_pair.client.request_key_update }
    failed = connected.client
    failed.discard
    assert_raises(TLS::UsageError) { failed.request_key_update }
  end

  def test_thirty_two_in_a_row_and_no_more
    machine = connected.server
    32.times { machine.receive(NOT_REQUESTED, epoch: :application, now: NOW) }
    refute machine.failed?
    machine.application_data_received
    32.times { machine.receive(REQUESTED, epoch: :application, now: NOW) }
    refute machine.failed?
    machine.receive(NOT_REQUESTED, epoch: :application, now: NOW)
    assert machine.failed?
    assert_equal TLS::Event::Failed.new(alert: :unexpected_message, reason: :too_many_key_updates), failure(machine)
    assert_equal [:alert, :application, :unexpected_message], Pair.shape(machine.outputs).last
    machine.before_application_data
    assert_empty machine.outputs
  end

  # RFC 9846: a KeyUpdate changes keys, so it ends its record. Each
  # `receive` over TCP is one record, and nothing is answered or owed.
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
