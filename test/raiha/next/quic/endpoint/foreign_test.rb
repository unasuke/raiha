require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# What the Endpoint of one of a server's workers hands on to another: the
# short header, Handshake and 0-RTT packets whose connection ID another
# worker issued, and nothing it takes itself or was handed already.
class RaihaNextQUICEndpointForeignTest < Minitest::Test
  include NextQUICPair

  KEYS = { retry_token_key: "r".b * 32, stateless_reset_key: "k".b * 32 }.freeze
  SCID = "s".b * 8

  def ids(worker) = QUIC::WorkerConnectionIDs.new(Random.new(worker), worker_id: worker, worker_count: 4, key: KEYS[:stateless_reset_key])

  # The Endpoint of worker 0 of 4.
  def endpoint = QUIC::Endpoint.server(config: QUIC::Config.new(**KEYS), random: Random.new(3), time: NOW, now: 0.0, connection_ids: ids(0))

  # A connection ID worker 2 issued.
  def theirs = @theirs ||= ids(2).generate(8)

  # A long header packet of `type` to `dcid` in a datagram of 1200 bytes.
  def long(type, dcid:)
    header = QUIC::Wire::LongHeader.new(type:, version: QUIC::Version::V1, dcid:, scid: SCID, token: "".b)
    keys = QUIC::Crypto::Initial.derive(dcid:, version: QUIC::Version::V1).client
    seal = ->(length) { QUIC::Wire::Packet.seal(header, packet_number: 0, packet_number_length: 2, payload: "\x01".b.ljust(length, "\0".b), keys:) }
    first = seal.(600)
    seal.(600 + 1200 - first.bytesize)
  end

  def short(dcid:, size: 100)
    keys = QUIC::Crypto::Keys.derive(suite: TLS::CipherSuite::TLS_AES_128_GCM_SHA256, secret: "x".b * 32, version: QUIC::Version::V1)
    QUIC::Wire::Packet.seal(QUIC::Wire::ShortHeader.new(dcid:), packet_number: 0, packet_number_length: 1,
      payload: "\x01".b.ljust(size - 1 - dcid.bytesize - 1 - 16, "\0".b), keys:)
  end

  def test_a_short_header_for_another_worker
    datagram = short(dcid: theirs)
    assert_equal QUIC::Route::Foreign.new(worker: 2, datagram:), endpoint.receive(datagram, from: CLIENT, to: SERVER, now: 0.0)
  end

  def test_handshake_and_zero_rtt_packets_for_another_worker
    %i[handshake zero_rtt].each do |type|
      datagram = long(type, dcid: theirs)
      assert_equal QUIC::Route::Foreign.new(worker: 2, datagram:), endpoint.receive(datagram, from: CLIENT, now: 0.0), type
    end
  end

  # A new connection's Initial is taken where it lands, whatever its
  # connection ID reads as.
  def test_an_initial_is_never_handed_on
    assert_instance_of QUIC::Route::Incoming, endpoint.receive(long(:initial, dcid: theirs), from: CLIENT, now: 0.0)
  end

  # What an offer of this worker has the connection ID of stays with it.
  def test_an_offer_comes_before_another_worker
    endpoint = endpoint()
    endpoint.receive(long(:initial, dcid: theirs), from: CLIENT, now: 0.0)
    assert_nil endpoint.receive(long(:zero_rtt, dcid: theirs), from: CLIENT, now: 0.0)
  end

  # What a worker handed on is not handed on again: the one it came to does
  # not know the connection ID either, and answers with a Stateless Reset.
  def test_what_was_handed_on_is_reset_rather_than_handed_on_again
    route = endpoint.receive(short(dcid: theirs), from: CLIENT, to: SERVER, now: 0.0, forwarded: true)
    assert_instance_of QUIC::Route::Respond, route
    assert QUIC::StatelessReset.match?(route.transmit.payload, [QUIC::StatelessReset.token(key: KEYS[:stateless_reset_key], connection_id: theirs)])
    assert_equal QUIC::Route::Drop.new(reason: :unknown_connection_id),
      endpoint.receive(long(:handshake, dcid: theirs), from: CLIENT, now: 0.0, forwarded: true)
  end

  def test_its_own_unknown_connection_id_is_reset
    assert_instance_of QUIC::Route::Respond, endpoint.receive(short(dcid: ids(0).generate(8)), from: CLIENT, to: SERVER, now: 0.0)
  end

  # A long header's connection ID of another length than the Endpoint
  # issues is no worker's.
  def test_a_connection_id_of_another_length
    dcid = ids(2).generate(12)
    assert_equal QUIC::Route::Drop.new(reason: :unknown_connection_id), endpoint.receive(long(:handshake, dcid:), from: CLIENT, now: 0.0)
  end
end
