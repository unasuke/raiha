require "test_helper"
require "support/quic_pair"

# RFC 9000 "Sending ACK Frames": an admitted offer acknowledges the
# client's Initial packets while the ClientHello is not whole, from the
# server's connection ID, which the client sends to from then.
class RaihaNextQUICEndpointEarlyAckTest < Minitest::Test
  include NextQUICPair

  SCID = "c".b * 8

  def endpoint = QUIC::Endpoint.server(config: QUIC::Config.new(stateless_reset_key: "k".b * 32), random: Random.new(3), time: NOW, now: 0.0)

  # A client's Initial of `size` bytes, or as few as it can be, to `dcid`
  # with `frames`, sealed with the Initial keys of `first`, the client's
  # first connection ID.
  def initial(first:, dcid:, packet_number:, frames:, size: 1200)
    header = QUIC::Wire::LongHeader.new(type: :initial, version: QUIC::Version::V1, dcid:, scid: SCID)
    keys = QUIC::Crypto::Initial.derive(dcid: first, version: QUIC::Version::V1).client
    payload = QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3)
    seal = ->(length) { QUIC::Wire::Packet.seal(header, packet_number:, packet_number_length: 2, payload: payload.ljust(length, "\0".b), keys:) }
    least = [payload.bytesize, 4].max
    seal.(least + [size - seal.(least).bytesize, 0].max)
  end

  # A client's ClientHello in two halves, and its first connection ID.
  def halves
    datagram = client_connection.transmits(now: 0.0).first.payload
    packet = QUIC::Wire::Packet.parse(datagram, dcid_length: 8)
    keys = QUIC::Crypto::Initial.derive(dcid: packet.header.dcid, version: QUIC::Version::V1).client
    payload = packet.unmask(keys.header_protection, largest: nil).open(keys.aead)
    hello = QUIC::Wire::Frame.parse(payload, packet_type: :initial, ack_delay_exponent: 3).grep(QUIC::Wire::Frame::Crypto).sum("".b, &:data)
    half = hello.bytesize / 2
    [[hello.byteslice(0, half), hello.byteslice(half..)], packet.header.dcid]
  end

  def crypto(offset, data) = QUIC::Wire::Frame::Crypto.new(offset:, data:)

  # Each datagram the Endpoint sent itself, as the header, packet number
  # and frames of the server's Initial packet to the client whose first
  # connection ID was `first`.
  def sent(endpoint, first)
    keys = QUIC::Crypto::Initial.derive(dcid: first, version: QUIC::Version::V1).server
    [].tap { |all| endpoint.each_transmit(now: 0.0) { all << _1 } }.map do |transmit|
      assert_equal CLIENT, transmit.destination
      unmasked = QUIC::Wire::Packet.parse(transmit.payload, dcid_length: 8).unmask(keys.header_protection, largest: nil)
      frames = QUIC::Wire::Frame.parse(unmasked.open(keys.aead), packet_type: :initial, ack_delay_exponent: 3)
      [unmasked.header, unmasked.packet_number, frames, transmit.payload.bytesize]
    end
  end

  # The first half admitted is acknowledged at once, in a datagram of no
  # padding; the second half comes to the server's connection ID, which
  # the connection takes, and its Initial packets follow the ACK's.
  def test_an_ack_while_the_client_hello_is_not_whole
    (one, two), first = halves
    endpoint = endpoint()
    handle = endpoint.receive(initial(first:, dcid: first, packet_number: 0, frames: [crypto(0, one)]), from: CLIENT, now: 0.0).handle
    assert_nil endpoint.admit(handle, now: 0.0)
    (header, number, frames, size), = sent(endpoint, first)
    server_id = header.scid
    assert_equal [SCID, 0, [0..0]], [header.dcid, number, frames.grep(QUIC::Wire::Frame::Ack).first.ranges]
    assert_operator size, :<, 100
    assert_equal server_id, handle.server_connection_id
    route = endpoint.receive(initial(first:, dcid: server_id, packet_number: 1, frames: [crypto(one.bytesize, two)]), from: CLIENT, now: 0.01)
    assert_instance_of QUIC::Route::ClientHello, route
    assert_empty sent(endpoint, first)
    tls_config = server_config
    connection = endpoint.accept(handle, tls_config:, keyring: server_keyring(config: tls_config), now: 0.01)
    keys = QUIC::Crypto::Initial.derive(dcid: first, version: QUIC::Version::V1).server
    flight = connection.transmits(now: 0.01).first.payload
    unmasked = QUIC::Wire::Packet.parse(flight, dcid_length: 8).unmask(keys.header_protection, largest: nil)
    assert_equal [server_id, 1], [unmasked.header.scid, unmasked.packet_number]
  end

  # A refusal after an ACK comes from the same connection ID, with the
  # next packet number, and forgets the offer by both its IDs.
  def test_a_refusal_after_an_ack
    (one, _), first = halves
    endpoint = endpoint()
    handle = endpoint.receive(initial(first:, dcid: first, packet_number: 0, frames: [crypto(0, one)]), from: CLIENT, now: 0.0).handle
    endpoint.admit(handle, now: 0.0)
    (ack, = sent(endpoint, first))
    endpoint.refuse(handle)
    (header, number, frames, _), = sent(endpoint, first)
    assert_equal [ack.first.scid, 1], [header.scid, number]
    assert_equal QUIC::ErrorCode::CONNECTION_REFUSED, frames.grep(QUIC::Wire::Frame::ConnectionClose).first.code
    late = initial(first:, dcid: ack.first.scid, packet_number: 1, frames: [QUIC::Wire::Frame::Ping.new])
    refute_kind_of QUIC::Route::ClientHello, endpoint.receive(late, from: CLIENT, now: 0.01)
  end

  # An offer that acknowledged the client's Initials and that no one
  # decided on is refused when it expires, from the server's connection
  # ID, and is forgotten by both its IDs, with what it kept.
  def test_an_acknowledged_offer_that_expires
    (one, _), first = halves
    endpoint = endpoint()
    handle = endpoint.receive(initial(first:, dcid: first, packet_number: 0, frames: [crypto(0, one)]), from: CLIENT, now: 0.0).handle
    endpoint.admit(handle, now: 0.0)
    (ack, = sent(endpoint, first))
    endpoint.handle_timeout(now: QUIC::Endpoint::HANDLE_LIFETIME)
    (header, number, frames, _), = sent(endpoint, first)
    assert_equal [ack.first.scid, 1], [header.scid, number]
    assert_equal QUIC::ErrorCode::CONNECTION_REFUSED, frames.grep(QUIC::Wire::Frame::ConnectionClose).first.code
    assert_raises(QUIC::Error::StateError) { endpoint.refuse(handle) }
    assert_nil endpoint.next_timeout
    assert_equal 0, endpoint.instance_variable_get(:@buffered)
  end

  # RFC 9000 "Datagram Size": an Initial of the offer's in a datagram
  # under 1200 bytes is dropped, and not acknowledged.
  def test_no_ack_of_a_short_datagram
    (one, _), first = halves
    endpoint = endpoint()
    handle = endpoint.receive(initial(first:, dcid: first, packet_number: 0, frames: [crypto(0, one)]), from: CLIENT, now: 0.0).handle
    endpoint.admit(handle, now: 0.0)
    sent(endpoint, first)
    ping = initial(first:, dcid: handle.server_connection_id, packet_number: 1, frames: [QUIC::Wire::Frame::Ping.new], size: 0)
    assert_equal QUIC::Route::Drop.new(reason: :too_short), endpoint.receive(ping, from: CLIENT, now: 0.0)
    assert_empty sent(endpoint, first)
  end

  # Initial packets of a few bytes, each eliciting an ACK, and with gaps
  # between their numbers, which make each ACK longer, are answered no
  # further than three times what the offer kept: some go unanswered. The
  # Endpoint drops such datagrams before an offer reads them, so they are
  # given to the offer itself here.
  def test_the_acks_keep_to_the_amplification_limit
    (one, _), first = halves
    handle = QUIC::Endpoint::Handle.new(remote: CLIENT, version: QUIC::Version::V1, destination_connection_id: first, source_connection_id: SCID,
      original_destination_connection_id: first, retry_source_connection_id: nil, expires_at: 3.0, address_validated: false)
    give = lambda do |datagram|
      handle.keep(datagram, from: CLIENT, to: nil, ecn: :not_ect)
      handle.admitted? ? handle.read(datagram, time: NOW, dcid_length: 8, ecn: :not_ect, now: 0.0) : handle.admit(time: NOW, dcid_length: 8, now: 0.0)
      handle.choose_connection_id("s".b * 8) unless handle.server_connection_id
      handle.acknowledgment(now: 0.0)
    end
    sent = [give.(initial(first:, dcid: first, packet_number: 0, frames: [crypto(0, one)]))]
    (1..300).each do |number|
      sent << give.(initial(first:, dcid: "s".b * 8, packet_number: number * 2, frames: [QUIC::Wire::Frame::Ping.new], size: 0))
      assert_operator sent.compact.sum(&:bytesize), :<=, 3 * handle.buffered
    end
    assert_includes sent, nil
    assert_equal sent.compact.size, handle.early_acks.size
  end
end
