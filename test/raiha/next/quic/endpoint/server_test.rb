require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# 250 "Endpoint": what a server's Endpoint does with datagrams that belong
# to no connection.
class RaihaNextQUICEndpointServerTest < Minitest::Test
  include NextQUICPair

  DCID = "d".b * 8
  SCID = "s".b * 8

  def endpoint(config: QUIC::Config.new) = QUIC::Endpoint.server(config:, random: Random.new(3), time: NOW, now: 0.0)

  # A client's Initial with a PING in a datagram of `size` bytes.
  def initial(dcid: DCID, token: "".b, size: QUIC::Connection::MIN_INITIAL_DATAGRAM, type: :initial)
    header = QUIC::Wire::LongHeader.new(type:, version: QUIC::Version::V1, dcid:, scid: SCID, token:)
    keys = QUIC::Crypto::Initial.derive(dcid:, version: QUIC::Version::V1).client
    seal = ->(length) { QUIC::Wire::Packet.seal(header, packet_number: 0, packet_number_length: 2, payload: "\x01".b.ljust(length, "\0".b), keys:) }
    first = seal.(size / 2)
    seal.(size / 2 + size - first.bytesize)
  end

  # A long header in a version not supported, in a datagram of `size`
  # bytes.
  def unsupported(size:) = ([0xc0, 0x0a0a0a0a, 8].pack("CNC") + DCID + [8].pack("C") + SCID).ljust(size, "\0".b)

  # A short header packet of `size` bytes to the connection ID `dcid`.
  def short(dcid:, size:)
    keys = QUIC::Crypto::Keys.derive(suite: TLS::CipherSuite::TLS_AES_128_GCM_SHA256, secret: "x".b * 32, version: QUIC::Version::V1)
    QUIC::Wire::Packet.seal(QUIC::Wire::ShortHeader.new(dcid:), packet_number: 0, packet_number_length: 1,
      payload: "\x01".b.ljust(size - 1 - dcid.bytesize - 1 - 16, "\0".b), keys:)
  end

  def test_a_first_initial_is_offered
    datagram = client_connection.transmits(now: 0.0).first.payload
    header = QUIC::Wire::Packet.parse(datagram, dcid_length: 8).header
    route = endpoint.receive(datagram, from: CLIENT, to: SERVER, now: 0.0)
    assert_instance_of QUIC::Route::Incoming, route
    assert_equal CLIENT, route.remote
    refute route.address_validated
    handle = route.handle
    assert_equal header.dcid, handle.original_destination_connection_id
    assert_equal header.dcid, handle.destination_connection_id
    assert_equal header.scid, handle.source_connection_id
    assert_nil handle.retry_source_connection_id
    assert_equal [[datagram, CLIENT, SERVER, :not_ect]], handle.datagrams
  end

  # Later datagrams to the same connection ID are kept with the offer.
  def test_later_datagrams_go_with_the_offer
    endpoint = endpoint()
    handle = endpoint.receive(initial, from: CLIENT, now: 0.0).handle
    assert_nil endpoint.receive(initial, from: CLIENT, now: 0.0)
    assert_equal 2, handle.datagrams.size
  end

  # 250 "handle has a lifetime": an offer no one decides on goes after
  # HANDLE_LIFETIME seconds.
  def test_an_offer_expires
    endpoint = endpoint()
    endpoint.receive(initial, from: CLIENT, now: 0.0)
    assert_equal QUIC::Endpoint::HANDLE_LIFETIME, endpoint.next_timeout
    endpoint.handle_timeout(now: QUIC::Endpoint::HANDLE_LIFETIME)
    assert_nil endpoint.next_timeout
    assert_instance_of QUIC::Route::Incoming, endpoint.receive(initial, from: CLIENT, now: QUIC::Endpoint::HANDLE_LIFETIME)
  end

  # RFC 9000 "Datagram Size".
  def test_an_initial_under_1200_bytes
    assert_equal QUIC::Route::Drop.new(reason: :too_short), endpoint.receive(initial(size: 1199), from: CLIENT, now: 0.0)
  end

  def test_a_handshake_packet_of_no_connection
    assert_equal QUIC::Route::Drop.new(reason: :unknown_connection_id), endpoint.receive(initial(type: :handshake), from: CLIENT, now: 0.0)
  end

  def test_a_short_header_packet_of_no_connection
    assert_equal QUIC::Route::Drop.new(reason: :unknown_connection_id), endpoint.receive(short(dcid: "c".b * 8, size: 100), from: CLIENT, now: 0.0)
  end

  def test_an_unknown_version
    assert_equal QUIC::Route::Drop.new(reason: :unsupported_version), endpoint.receive(unsupported(size: 1200), from: CLIENT, now: 0.0)
  end

  # A server does not take a Version Negotiation.
  def test_a_version_negotiation
    datagram = QUIC::Wire::VersionNegotiation.new(dcid: DCID, scid: SCID, versions: [1]).encode
    assert_equal QUIC::Route::Drop.new(reason: :unexpected_packet), endpoint.receive(datagram, from: CLIENT, now: 0.0)
  end

  def test_bytes_that_do_not_read
    assert_equal QUIC::Route::Drop.new(reason: :malformed), endpoint.receive("\x00".b * 50, from: CLIENT, now: 0.0)
  end
end
