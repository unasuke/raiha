require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# The second stage of a new connection: an admitted offer reads the
# ClientHello out of its Initial packets.
class RaihaNextQUICEndpointAcceptTest < Minitest::Test
  include NextQUICPair

  SCID = "s".b * 8

  def endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: Random.new(3), time: NOW, now: 0.0)

  # The ClientHello a client's first Initial carries.
  def client_hello(datagram)
    packet = QUIC::Wire::Packet.parse(datagram, dcid_length: 8)
    keys = QUIC::Crypto::Initial.derive(dcid: packet.header.dcid, version: QUIC::Version::V1).client
    payload = packet.unmask(keys.header_protection, largest: nil).open(keys.aead)
    QUIC::Wire::Frame.parse(payload, packet_type: :initial, ack_delay_exponent: 3).grep(QUIC::Wire::Frame::Crypto).sum("".b, &:data)
  end

  # A client's Initial of 1200 bytes to `dcid` with `frames`.
  def initial(dcid:, packet_number:, frames:)
    header = QUIC::Wire::LongHeader.new(type: :initial, version: QUIC::Version::V1, dcid:, scid: SCID)
    keys = QUIC::Crypto::Initial.derive(dcid:, version: QUIC::Version::V1).client
    payload = QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3)
    seal = ->(length) { QUIC::Wire::Packet.seal(header, packet_number:, packet_number_length: 2, payload: payload.ljust(length, "\0".b), keys:) }
    first = seal.(payload.bytesize)
    seal.(payload.bytesize + 1200 - first.bytesize)
  end

  # The ClientHello of a client, split over two Initials to its first
  # connection ID.
  def split_client_hello
    first = client_connection.transmits(now: 0.0).first.payload
    dcid = QUIC::Wire::Packet.parse(first, dcid_length: 8).header.dcid
    hello = client_hello(first)
    half = hello.bytesize / 2
    [0, 1].map do |part|
      offset = part * half
      data = part.zero? ? hello.byteslice(0, half) : hello.byteslice(half..)
      initial(dcid:, packet_number: part, frames: [QUIC::Wire::Frame::Crypto.new(offset:, data:)])
    end
  end

  def test_admit_reads_the_client_hello
    endpoint = endpoint()
    handle = endpoint.receive(client_connection.transmits(now: 0.0).first.payload, from: CLIENT, now: 0.0).handle
    route = endpoint.admit(handle, now: 0.0)
    assert_instance_of QUIC::Route::ClientHello, route
    assert_same handle, route.handle
    assert_equal "localhost", route.accepted.info.server_name
    assert_equal ["hq-interop"], route.accepted.info.alpn_protocols
    assert_empty [].tap { |sent| endpoint.each_transmit(now: 0.0) { sent << _1 } }
  end

  # A ClientHello over two datagrams is whole when the second comes, after
  # the offer is admitted or before.
  def test_a_client_hello_over_two_datagrams
    first, second = split_client_hello
    endpoint = endpoint()
    handle = endpoint.receive(first, from: CLIENT, now: 0.0).handle
    assert_nil endpoint.admit(handle, now: 0.0)
    route = endpoint.receive(second, from: CLIENT, now: 0.0)
    assert_equal "localhost", route.accepted.info.server_name
    assert_nil endpoint.receive(second, from: CLIENT, now: 0.0)

    endpoint = endpoint()
    handle = endpoint.receive(first, from: CLIENT, now: 0.0).handle
    assert_nil endpoint.receive(second, from: CLIENT, now: 0.0)
    assert_instance_of QUIC::Route::ClientHello, endpoint.admit(handle, now: 0.0)
  end

  def test_an_offer_is_admitted_once
    endpoint = endpoint()
    handle = endpoint.receive(client_connection.transmits(now: 0.0).first.payload, from: CLIENT, now: 0.0).handle
    endpoint.admit(handle, now: 0.0)
    assert_raises(QUIC::Error::StateError) { endpoint.admit(handle, now: 0.0) }
  end

  def test_an_expired_offer_is_not_admitted
    endpoint = endpoint()
    handle = endpoint.receive(client_connection.transmits(now: 0.0).first.payload, from: CLIENT, now: 0.0).handle
    endpoint.handle_timeout(now: QUIC::Endpoint::HANDLE_LIFETIME)
    assert_raises(QUIC::Error::StateError) { endpoint.admit(handle, now: QUIC::Endpoint::HANDLE_LIFETIME) }
  end

  # A ClientHello the Acceptor fails on ends the offer.
  def test_a_broken_client_hello
    endpoint = endpoint()
    datagram = initial(dcid: "d".b * 8, packet_number: 0, frames: [QUIC::Wire::Frame::Crypto.new(offset: 0, data: "\x01\x00\x00\x05hello".b)])
    handle = endpoint.receive(datagram, from: CLIENT, now: 0.0).handle
    assert_nil endpoint.admit(handle, now: 0.0)
    assert_nil endpoint.next_timeout
    assert_raises(QUIC::Error::StateError) { endpoint.admit(handle, now: 0.0) }
  end

  # CRYPTO data past what an Acceptor takes ends the offer.
  def test_crypto_past_the_limit
    endpoint = endpoint()
    offset = TLS::Handshake::Acceptor::MAX_CLIENT_HELLO_SIZE
    datagram = initial(dcid: "d".b * 8, packet_number: 0, frames: [QUIC::Wire::Frame::Crypto.new(offset:, data: "x".b)])
    handle = endpoint.receive(datagram, from: CLIENT, now: 0.0).handle
    assert_nil endpoint.admit(handle, now: 0.0)
    assert_nil endpoint.next_timeout
  end
end
