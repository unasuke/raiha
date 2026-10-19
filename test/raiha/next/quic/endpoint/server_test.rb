require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# 250 "Endpoint": what a server's Endpoint does with datagrams that belong
# to no connection.
class RaihaNextQUICEndpointServerTest < Minitest::Test
  include NextQUICPair

  KEYS = { retry_token_key: "r".b * 32, stateless_reset_key: "k".b * 32 }.freeze
  DCID = "d".b * 8
  SCID = "s".b * 8

  def endpoint(config: QUIC::Config.new(**KEYS)) = QUIC::Endpoint.server(config:, random: Random.new(3), time: NOW, now: 0.0)

  # A client's Initial with a PING in a datagram of `size` bytes.
  def initial(dcid: DCID, token: "".b, size: QUIC::Connection::MIN_INITIAL_DATAGRAM, type: :initial)
    header = QUIC::Wire::LongHeader.new(type:, version: QUIC::Version::V1, dcid:, scid: SCID, token:)
    keys = QUIC::Crypto::Initial.derive(dcid:, version: QUIC::Version::V1).client
    seal = ->(length) { QUIC::Wire::Packet.seal(header, packet_number: 0, packet_number_length: 2, payload: "\x01".b.ljust(length, "\0".b), keys:) }
    first = seal.(size / 2)
    seal.(size / 2 + size - first.bytesize)
  end

  # An Initial of 1200 bytes to `dcid` that the first stage takes, sealed
  # with keys of another connection ID, which it does not look at.
  def fast_initial(dcid)
    @fast_keys ||= QUIC::Crypto::Initial.derive(dcid: DCID, version: QUIC::Version::V1).client
    header = QUIC::Wire::LongHeader.new(type: :initial, version: QUIC::Version::V1, dcid:, scid: SCID)
    QUIC::Wire::Packet.seal(header, packet_number: 0, packet_number_length: 2, payload: "\x01".b.ljust(1156, "\0".b), keys: @fast_keys)
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

  # Later datagrams to the same connection ID are kept with the offer, up
  # to HANDLE_BUFFER bytes.
  def test_later_datagrams_go_with_the_offer
    endpoint = endpoint()
    handle = endpoint.receive(initial, from: CLIENT, now: 0.0).handle
    kept = QUIC::Endpoint::HANDLE_BUFFER / QUIC::Connection::MIN_INITIAL_DATAGRAM
    (kept - 1).times { assert_nil endpoint.receive(initial, from: CLIENT, now: 0.0) }
    assert_equal kept, handle.datagrams.size
    assert_equal QUIC::Route::Drop.new(reason: :buffer_full), endpoint.receive(initial, from: CLIENT, now: 0.0)
  end

  # An offer keeps only what its client sends before the server answers:
  # Initial and 0-RTT packets from the address of the first.
  def test_an_offer_keeps_only_its_client
    endpoint = endpoint()
    handle = endpoint.receive(initial, from: CLIENT, now: 0.0).handle
    assert_equal QUIC::Route::Drop.new(reason: :address_mismatch), endpoint.receive(initial, from: ["203.0.113.66", 4444], now: 0.0)
    assert_equal QUIC::Route::Drop.new(reason: :unexpected_packet), endpoint.receive(initial(type: :handshake), from: CLIENT, now: 0.0)
    assert_nil endpoint.receive(initial(type: :zero_rtt), from: CLIENT, now: 0.0)
    assert_equal 2, handle.datagrams.size
  end

  # All offers together keep HANDLES_BUFFER bytes at most; what an offer
  # kept is let go with it.
  def test_all_offers_keep_a_bounded_amount
    endpoint = endpoint()
    offers = QUIC::Endpoint::HANDLES_BUFFER / QUIC::Connection::MIN_INITIAL_DATAGRAM
    offers.times { |i| assert_instance_of QUIC::Route::Incoming, endpoint.receive(fast_initial([i].pack("Q>")), from: CLIENT, now: 0.0) }
    assert_equal QUIC::Route::Drop.new(reason: :buffer_full), endpoint.receive(fast_initial("x".b * 8), from: CLIENT, now: 0.0)
    endpoint.handle_timeout(now: QUIC::Endpoint::HANDLE_LIFETIME)
    assert_instance_of QUIC::Route::Incoming, endpoint.receive(fast_initial("x".b * 8), from: CLIENT, now: QUIC::Endpoint::HANDLE_LIFETIME)
  end

  # RFC 9000 "Negotiating Connection IDs": a client's first Destination
  # Connection ID has 8 bytes at least; after a Retry it is the server's,
  # of the length the server chose.
  def test_a_short_first_connection_id
    endpoint = endpoint(config: QUIC::Config.new(**KEYS, connection_id_length: 4))
    assert_equal QUIC::Route::Drop.new(reason: :short_connection_id), endpoint.receive(initial(dcid: "d".b * 7), from: CLIENT, now: 0.0)
    token = QUIC::RetryToken.mint(key: KEYS[:retry_token_key], original_destination_connection_id: "o".b * 8, address: CLIENT, time: NOW)
    assert_instance_of QUIC::Route::Incoming, endpoint.receive(initial(dcid: "r".b * 4, token:), from: CLIENT, now: 0.0)
  end

  # RFC 9000 "Address Validation Using Retry Packets": a Retry token shows
  # the address, and carries the client's first Destination Connection ID.
  def test_a_retry_token
    token = QUIC::RetryToken.mint(key: KEYS[:retry_token_key], original_destination_connection_id: "o".b * 8, address: CLIENT, time: NOW)
    route = endpoint.receive(initial(token:), from: CLIENT, now: 0.0)
    assert route.address_validated
    assert_equal "o".b * 8, route.handle.original_destination_connection_id
    assert_equal DCID, route.handle.retry_source_connection_id
  end

  def test_a_retry_token_for_another_address
    token = QUIC::RetryToken.mint(key: KEYS[:retry_token_key], original_destination_connection_id: "o".b * 8, address: SERVER, time: NOW)
    assert_equal QUIC::Route::Drop.new(reason: :invalid_token), endpoint.receive(initial(token:), from: CLIENT, now: 0.0)
  end

  def test_an_expired_retry_token
    token = QUIC::RetryToken.mint(key: KEYS[:retry_token_key], original_destination_connection_id: "o".b * 8, address: CLIENT, time: NOW)
    later = QUIC::RetryToken::LIFETIME + 1.0
    assert_equal QUIC::Route::Drop.new(reason: :invalid_token), endpoint.receive(initial(token:), from: CLIENT, now: later)
  end

  # A token of another kind, as NEW_TOKEN gives, is as none.
  def test_another_token
    route = endpoint.receive(initial(token: "\x01token".b), from: CLIENT, now: 0.0)
    refute route.address_validated
    assert_equal DCID, route.handle.original_destination_connection_id
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

  # RFC 9000 "Stateless Reset": a short header packet of no connection is
  # answered with a reset whose token comes from its connection ID, 42
  # bytes at most and shorter than the packet.
  def test_a_stateless_reset
    route = endpoint.receive(short(dcid: "c".b * 8, size: 100), from: CLIENT, to: SERVER, now: 0.0)
    assert_equal [CLIENT, SERVER], [route.transmit.destination, route.transmit.source]
    reset = route.transmit.payload
    assert_equal QUIC::Endpoint::MAX_RESET_LENGTH, reset.bytesize
    assert_equal 0x40, reset.getbyte(0) & 0xc0
    assert QUIC::StatelessReset.match?(reset, [QUIC::StatelessReset.token(key: KEYS[:stateless_reset_key], connection_id: "c".b * 8)])
    assert_equal 29, endpoint.receive(short(dcid: "c".b * 8, size: 30), from: CLIENT, now: 0.0).transmit.payload.bytesize
  end

  # RFC 9000 "Looping": each address has RESET_BURST resets, refilled at
  # RESET_RATE a second.
  def test_resets_are_limited_by_address
    endpoint = endpoint()
    packet = short(dcid: "c".b * 8, size: 100)
    QUIC::Endpoint::RESET_BURST.to_i.times { assert_instance_of QUIC::Route::Respond, endpoint.receive(packet, from: CLIENT, now: 0.0) }
    assert_equal QUIC::Route::Drop.new(reason: :reset_rate_limited), endpoint.receive(packet, from: CLIENT, now: 0.0)
    assert_instance_of QUIC::Route::Respond, endpoint.receive(packet, from: ["192.0.2.9", 9], now: 0.0)
    assert_instance_of QUIC::Route::Respond, endpoint.receive(packet, from: CLIENT, now: 1.0 / QUIC::Endpoint::RESET_RATE)
  end

  # At most RESET_ADDRESSES addresses are kept; a new one gets a reset once
  # a bucket has filled up again.
  def test_the_addresses_kept_for_resets_are_bounded
    endpoint = endpoint()
    packet = short(dcid: "c".b * 8, size: 100)
    QUIC::Endpoint::RESET_ADDRESSES.times { endpoint.receive(packet, from: ["198.51.100.1", _1], now: 0.0) }
    assert_equal QUIC::Route::Drop.new(reason: :reset_rate_limited), endpoint.receive(packet, from: CLIENT, now: 0.0)
    assert_instance_of QUIC::Route::Respond, endpoint.receive(packet, from: CLIENT, now: 1.0 / QUIC::Endpoint::RESET_RATE)
  end

  # RFC 9000 "Version Negotiation": the versions supported, the connection
  # IDs echoed in each other's places.
  def test_an_unknown_version
    route = endpoint.receive(unsupported(size: 1200), from: CLIENT, to: SERVER, now: 0.0)
    assert_equal CLIENT, route.transmit.destination
    assert_equal SERVER, route.transmit.source
    negotiation = QUIC::Wire::Packet.parse(route.transmit.payload, dcid_length: 8)
    assert_equal QUIC::Wire::VersionNegotiation.new(dcid: SCID, scid: DCID, versions: [QUIC::Version::V1.number]), negotiation
  end

  def test_an_unknown_version_in_a_small_datagram
    assert_equal QUIC::Route::Drop.new(reason: :too_short), endpoint.receive(unsupported(size: 1199), from: CLIENT, now: 0.0)
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
