require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9000 "Address Validation Using Retry Packets", as a client takes a
# Retry from a server's Endpoint.
class RaihaNextQUICConnectionRetryTest < Minitest::Test
  include NextQUICPair

  def endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: Random.new(3), time: NOW, now: 0.0)

  # An application that answers an offer whose address is not validated
  # with a Retry, and takes the others.
  def dispatch(endpoint, route, now)
    case route
    in QUIC::Route::Incoming(handle:, address_validated: false) then endpoint.retry(handle, now:)
    in QUIC::Route::Incoming(handle:) then dispatch(endpoint, endpoint.admit(handle, now:), now)
    in QUIC::Route::ClientHello(handle:)
      tls_config = server_config
      @server = endpoint.accept(handle, tls_config:, keyring: server_keyring(config: tls_config), now:)
    else nil
    end
  end

  # Passes datagrams between `client` and `endpoint` until the handshake
  # is done or `rounds` have gone.
  def exchange(client, endpoint, rounds: 20)
    now = 0.0
    rounds.times do
      break if client.handshake_complete? && @server&.handshake_complete?
      client.transmits(now:).each { dispatch(endpoint, endpoint.receive(_1.payload, from: CLIENT, to: SERVER, now:), now) }
      endpoint.each_transmit(now:) { client.receive(_1.payload, from: SERVER, now:) }
      now += 0.001
    end
  end

  # The header of the client's next Initial, sent at `now` or when its PTO
  # runs out after, and the time it was sent.
  def next_initial(client, now:)
    sent = client.transmits(now:)
    if sent.empty?
      now = client.next_timeout
      client.handle_timeout(now:)
      sent = client.transmits(now:)
    end
    [QUIC::Wire::Packet.parse(sent.first.payload, dcid_length: 8).header, now]
  end

  def test_a_handshake_after_a_retry
    client = client_connection
    exchange(client, endpoint)
    assert client.handshake_complete?
    assert @server.handshake_complete?
    assert_nil client.close_reason
  end

  # After a Retry, the client's Initials go to the Retry's connection ID
  # with its token, and carry the ClientHello again.
  def test_the_initials_after_a_retry
    client = client_connection
    first = QUIC::Wire::Packet.parse(client.transmits(now: 0.0).first.payload, dcid_length: 8).header
    retry_packet = QUIC::Wire::Retry.new(version: QUIC::Version::V1, dcid: first.scid, scid: "r".b * 8, token: "t".b)
    client.receive(retry_packet.seal(first.dcid), from: SERVER, now: 0.01)
    header, now = next_initial(client, now: 0.01)
    assert_equal 0.01, now
    assert_equal ["r".b * 8, "t".b], [header.dcid, header.token]
  end

  # RFC 9000 "Retry Packet": a client takes one Retry, with the tag of its
  # first connection ID, and none once a packet of the server has opened.
  # A token from a NEW_TOKEN frame goes in the client's Initials until a
  # Retry's takes its place (RFC 9000 "Address Validation for Future
  # Connections").
  def test_a_token_from_new_token
    token = "\x01".b + "t".b * 40
    header, = next_initial(client_connection(token:), now: 0.0)
    assert_equal token, header.token
    # A server that does not take it sends a Retry, whose token the client
    # carries then.
    client = client_connection(token:)
    exchange(client, endpoint)
    assert client.handshake_complete?
    assert_raises(ArgumentError) { client_connection(token: "".b) }
  end

  KEY = "\x07".b * 32

  # The route of the client's first Initial with `token` to a server whose
  # retry_token_key is KEY.
  def route_with(token)
    endpoint = QUIC::Endpoint.server(config: QUIC::Config.new(retry_token_key: KEY), random: Random.new(3), time: NOW, now: 0.0)
    endpoint.receive(client_connection(token:).transmits(now: 0.0).first.payload, from: CLIENT, to: SERVER, now: 0.0)
  end

  def new_token(address: CLIENT, version: QUIC::Version::V1.number, time: NOW)
    QUIC::NewToken.mint(key: QUIC::NewToken.key(KEY), address:, version:, time:, random: Random.new(4))
  end

  # A token of NEW_TOKEN the server made validates the client's address; one
  # that is not valid is as none, with no INVALID_TOKEN, and the server may
  # still send a Retry.
  def test_a_new_token_validates_the_address
    assert_equal true, route_with(new_token).address_validated
    [new_token(address: ["192.0.2.9", 50_000]), new_token(time: NOW - QUIC::NewToken::LIFETIME - 1),
      new_token(version: 0x6b3343cf), "\x01".b + "x".b * 40].each do |token|
      route = route_with(token)
      assert_instance_of QUIC::Route::Incoming, route
      assert_equal false, route.address_validated
    end
  end

  def test_retries_the_client_does_not_take
    client = client_connection
    first = QUIC::Wire::Packet.parse(client.transmits(now: 0.0).first.payload, dcid_length: 8).header
    forged = QUIC::Wire::Retry.new(version: QUIC::Version::V1, dcid: first.scid, scid: "f".b * 8, token: "f".b)
    client.receive(forged.seal("x".b * 8), from: SERVER, now: 0.01)
    header, now = next_initial(client, now: 0.01)
    assert_equal [first.dcid, "".b], [header.dcid, header.token]
    taken = QUIC::Wire::Retry.new(version: QUIC::Version::V1, dcid: first.scid, scid: "r".b * 8, token: "t".b)
    client.receive(taken.seal(first.dcid), from: SERVER, now:)
    another = QUIC::Wire::Retry.new(version: QUIC::Version::V1, dcid: first.scid, scid: "a".b * 8, token: "a".b)
    client.receive(another.seal(first.dcid), from: SERVER, now:)
    header, = next_initial(client, now:)
    assert_equal ["r".b * 8, "t".b], [header.dcid, header.token]
  end

  def test_no_retry_after_the_server_answered
    client = client_connection
    server = server_connection
    first = client.transmits(now: 0.0).first.payload
    header = QUIC::Wire::Packet.parse(first, dcid_length: 8).header
    server.receive(first, from: CLIENT, now: 0.0)
    server.transmits(now: 0.0).each { client.receive(_1.payload, from: SERVER, now: 0.0) }
    retry_packet = QUIC::Wire::Retry.new(version: QUIC::Version::V1, dcid: header.scid, scid: "r".b * 8, token: "t".b)
    client.receive(retry_packet.seal(header.dcid), from: SERVER, now: 0.01)
    handshake(client, server)
    assert client.handshake_complete?
    assert_nil client.close_reason
  end
end
