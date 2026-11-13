require "test_helper"
require "support/tcp_pair"
require "stringio"

# KeyUpdate over TCP::Connection.
class RaihaNextTLSTCPKeyUpdateTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Pair = NextTCPPair
  NOW = Pair::NOW
  SUITE = TLS::CipherSuite::TLS_AES_128_GCM_SHA256

  # A connected pair whose client writes under a suite allowed only `limit`
  # records per key: the same key, put back with the smaller limit.
  def pair_with_client_limit(limit)
    keylog = StringIO.new
    pair = Pair.connect(client: Pair.client(keylog:))
    secret = [keylog.string.lines.grep(/\ACLIENT_TRAFFIC_SECRET_0/).first.split.last].pack("H*")
    limits = { tcp: TLS::CipherSuite::Limits.new(confidentiality: limit, integrity: nil), quic: SUITE.limits.fetch(:quic) }
    record = pair.client.instance_variable_get(:@record)
    record.install(direction: :write, epoch: :application, secret:, cipher_suite: SUITE.with(limits:))
    pair
  end

  def test_request_key_update
    pair = Pair.connect
    pair.client.request_key_update
    sent = Pair.take(pair.client)
    # The KeyUpdate message alone: 5 bytes, its content type and the tag.
    assert_equal [[23, 22]], Pair.records(sent)
    pair.server.receive(sent, now: NOW)
    pair.client.write("after")
    Pair.pump(pair.client, pair.server)
    refute pair.server.failed?
    assert_equal "after", pair.server.read(10)
    assert_raises(TLS::UsageError) { Pair.client.request_key_update }
  end

  # Asked for one, the server answers right before its next application
  # data, and not before.
  def test_an_owed_key_update_goes_before_application_data
    pair = Pair.connect
    pair.client.request_key_update(request_peer_update: true)
    Pair.pump(pair.client, pair.server)
    assert_empty Pair.take(pair.server)
    pair.server.write("x")
    sent = Pair.take(pair.server)
    assert_equal [[23, 22], [23, 18]], Pair.records(sent)
    pair.client.receive(sent, now: NOW)
    refute pair.client.failed?
    assert_equal "x", pair.client.read(10)
  end

  # 32 KeyUpdates in a row, then data, then 32 more: the run starts over.
  # The 33rd in a row ends the connection.
  def test_runs_of_key_updates
    pair = Pair.connect
    32.times { pair.server.request_key_update }
    pair.server.write("x")
    32.times { pair.server.request_key_update }
    pair.client.receive(Pair.take(pair.server), now: NOW)
    refute pair.client.failed?
    pair.server.request_key_update
    pair.client.receive(Pair.take(pair.server), now: NOW)
    assert pair.client.failed?
    assert_equal TLS::Event::Failed.new(alert: :unexpected_message, reason: :too_many_key_updates),
      Pair.events(pair.client).grep(TLS::Event::Failed).first
  end

  # RFC 9846 "Limits on Key Usage": with room for 3 records under the first
  # key, the third is a KeyUpdate, and the peer follows it. The next key
  # comes from the Machine with the suite's own limit.
  def test_keys_change_before_the_limit
    pair = pair_with_client_limit(3)
    data = "a" * (16_384 * 3 + 100)
    assert_equal data.bytesize, pair.client.write(data)
    # Two records, the KeyUpdate, the rest under the next key.
    assert_equal [16_401, 16_401, 22, 16_401, 117], Pair.records(sent = Pair.take(pair.client)).map(&:last)
    assert_equal 1, pair.client.instance_variable_get(:@machine).key_update_epoch
    pair.client.write("b")
    assert_equal [1 + 1 + 16], Pair.records(more = Pair.take(pair.client)).map(&:last)
    pair.server.receive(sent + more, now: NOW)
    refute pair.server.failed?
    assert_equal data + "b", pair.server.read(1 << 20)
  end
end
