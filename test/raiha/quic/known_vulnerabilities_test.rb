require "test_helper"
require "support/quic_pair"
require "objspace"

# What other implementations of QUIC were broken by, each tried on this
# one at the handshake: frames that fill memory, state taken before the
# client's address is validated, packets of the other role, and the order
# of the calls of the application. The bounds of CRYPTO reassembly in
# themselves are tested with CryptoStream, the end of an offer with the
# Endpoint, and HANDSHAKE_DONE from a client with the handshake.
class RaihaQUICKnownVulnerabilitiesTest < Minitest::Test
  include QUICPair

  # A client's Initial to `dcid` with `frames`, padded to 1200 bytes.
  def initial(dcid:, frames:, packet_number: 1)
    header = QUIC::Wire::LongHeader.new(type: :initial, version: QUIC::Version::V1, dcid:, scid: "c".b * 8)
    keys = QUIC::Crypto::Initial.derive(dcid:, version: QUIC::Version::V1).client
    payload = QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3)
    first = QUIC::Wire::Packet.seal(header, packet_number:, packet_number_length: 2, payload:, keys:)
    QUIC::Wire::Packet.seal(header, packet_number:, packet_number_length: 2, payload: payload.ljust(payload.bytesize + 1200 - first.bytesize, "\0".b), keys:)
  end

  # A CRYPTO frame far past what is read is CRYPTO_BUFFER_EXCEEDED before
  # anything of its offset is taken.
  def test_crypto_far_ahead
    server = server_connection
    server.receive(initial(dcid: "d".b * 8, frames: [QUIC::Wire::Frame::Crypto.new(offset: 0, data: "\x01".b)]), from: CLIENT, now: 0.0)
    far = QUIC::Wire::Frame::Crypto.new(offset: 1 << 40, data: "x".b)
    server.receive(initial(dcid: "d".b * 8, frames: [far], packet_number: 2), from: CLIENT, now: 0.0)
    assert_equal QUIC::ErrorCode::CRYPTO_BUFFER_EXCEEDED, server.close_reason&.code
  end

  # CRYPTO data is kept in a String of its own, never as a part of the
  # datagram it came in, which a substring of it to its end would keep
  # whole (CVE-2026-54873).
  def test_crypto_data_does_not_keep_the_datagram
    datagram = "\x01".b * 5000
    tail = datagram.byteslice(1000..)
    assert ObjectSpace.dump(tail).include?('"shared":true'), "a substring to the end is shared"
    stream = QUIC::CryptoStream.new(:initial)
    stream.receive(0, tail, limit: 8192)
    refute ObjectSpace.dump(stream.instance_variable_get(:@window)).include?('"shared":true'), "the CRYPTO data is shared"
  end

  # The first stage of a new connection derives no key, so that an
  # attacker's Initials cost the server their headers alone.
  def test_the_first_stage_derives_no_key
    # A prepended module stays once the test is over, so it counts only for
    # the thread of this test, and writes nothing to the class: the workers
    # of other tests derive keys in Ractors, where it could not.
    counter = Module.new do
      def derive(...)
        counts = Thread.current[:raiha_next_initial_derives]
        counts << 1 if counts
        super
      end
    end
    QUIC::Crypto::Initial.singleton_class.prepend(counter)
    endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: Random.new(3), time: NOW, now: 0.0)
    datagram = client_connection.transmits(now: 0.0).first.payload
    derives = Thread.current[:raiha_next_initial_derives] = []
    assert_instance_of QUIC::Route::Incoming, endpoint.receive(datagram, from: CLIENT, now: 0.0)
    assert_empty derives
  ensure
    Thread.current[:raiha_next_initial_derives] = nil
  end

  # A client's Initial packet to `dcid` with a PING, of `size` bytes.
  def ping(dcid:, packet_number:, size:)
    header = QUIC::Wire::LongHeader.new(type: :initial, version: QUIC::Version::V1, dcid:, scid: "c".b * 8)
    keys = QUIC::Crypto::Initial.derive(dcid:, version: QUIC::Version::V1).client
    seal = ->(length) { QUIC::Wire::Packet.seal(header, packet_number:, packet_number_length: 2, payload: "\x01".b.ljust(length, "\0".b), keys:) }
    seal.(size - (seal.(100).bytesize - 100))
  end

  # A datagram of four coalesced packets lets a server whose client's
  # address is not validated send three times its length more, once for
  # the datagram, not for each packet in it (CVE-2026-35191). The server's
  # certificate chain makes it want to send far more.
  def test_the_amplification_limit_counts_each_datagram_once
    identity = TLSPair.server_identity
    long = TLS::Keyring::Identity.new(cert_der: identity.cert_der + [TLSPair.ca.der] * 8, key_der: identity.key_der)
    tls_config = server_config
    keyring = TLS::Keyring.server(config: tls_config, identities: [long], random: Random.new(2))
    server = QUIC::Connection.server(config: QUIC::Config.new, tls_config:, keyring:, time: NOW, now: 0.0)
    first = client_connection.transmits(now: 0.0).first.payload
    dcid = QUIC::Wire::Packet.parse(first, dcid_length: 8).header.dcid
    server.receive(first, from: CLIENT, now: 0.0)
    sent = server.transmits(now: 0.0).sum { _1.payload.bytesize }
    coalesced = (2..5).map { ping(dcid:, packet_number: _1, size: 300) }.join
    assert_equal 1200, coalesced.bytesize
    server.receive(coalesced, from: CLIENT, now: 0.01)
    sent += server.transmits(now: 0.01).sum { _1.payload.bytesize }
    assert_operator sent, :<=, 3 * (first.bytesize + coalesced.bytesize)
    assert_operator sent, :>, 3 * first.bytesize
  end

  # A server takes no packet that only a client takes: a Retry or a
  # Version Negotiation is dropped.
  def test_a_server_takes_no_retry_or_version_negotiation
    client = client_connection
    server = server_connection
    first = client.transmits(now: 0.0).first.payload
    header = QUIC::Wire::Packet.parse(first, dcid_length: 8).header
    server.receive(first, from: CLIENT, now: 0.0)
    server_id = QUIC::Wire::Packet.parse(server.transmits(now: 0.0).first.payload, dcid_length: 8).header.scid
    retry_packet = QUIC::Wire::Retry.new(version: QUIC::Version::V1, dcid: server_id, scid: "r".b * 8, token: "t".b).seal(header.scid)
    negotiation = QUIC::Wire::VersionNegotiation.new(dcid: server_id, scid: header.scid, versions: [0x0a0a0a0a]).encode
    server.receive(retry_packet, from: CLIENT, now: 0.01)
    server.receive(negotiation, from: CLIENT, now: 0.01)
    refute server.closed?
    assert_nil server.close_reason
  end

  # An application may stop taking datagrams halfway and run a timer out
  # before it takes the rest: the handshake goes on as before (by analogy
  # with CVE-2026-84782).
  def test_a_timer_between_datagrams
    client = client_connection
    server = server_connection
    now = 0.0
    20.times do
      break if client.handshake_complete? && server.handshake_complete?
      server.each_transmit(now:) do |transmit|
        client.receive(transmit.payload, from: SERVER, now:)
        break
      end
      timeout = server.next_timeout
      server.handle_timeout(now: now = timeout) if timeout && timeout < now + 1.5
      server.transmits(now:).each { client.receive(_1.payload, from: SERVER, now:) }
      client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now:) }
      now += 0.001
    end
    assert client.handshake_complete?
    assert server.handshake_complete?
  end

  # An issuer of connection IDs of a count, which keeps those it forgot.
  class Issuer
    attr_reader :forgotten

    def initialize
      @count = 0
      @forgotten = []
    end

    def issue(_connection) = [format("%08d", @count += 1).b, "t".b * 16]

    def forget(connection_id) = @forgotten << connection_id
  end

  # A server done with the handshake, its connection ID "s" * 8 and its
  # IDs issued by `issuer`; the client's key log; and the time.
  def issuing_server(issuer)
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection(source_connection_id: "s".b * 8, issuer:)
    now = handshake(client, server)
    [server, keylog, now]
  end

  # A client's 1-RTT packet to "s" * 8 that retires `sequence_number`.
  def retire(keylog, sequence_number, packet_number:)
    payload = QUIC::Wire::Frame.encode([QUIC::Wire::Frame::RetireConnectionID.new(sequence_number:)], ack_delay_exponent: 3)
    client_one_rtt(keylog, dcid: "s".b * 8, payload:, packet_number:)
  end

  # RETIRE_CONNECTION_ID of the ID of its own packet is PROTOCOL_VIOLATION,
  # so that the ends do not retire and replace for ever (CVE-2025-7054);
  # so is a sequence number never issued, and one retired again is nothing.
  def test_retire_connection_id_of_its_own_packet
    server, keylog, now = issuing_server(Issuer.new)
    server.receive(retire(keylog, 1, packet_number: 1000), from: CLIENT, now:)
    server.receive(retire(keylog, 1, packet_number: 1001), from: CLIENT, now:)
    assert_nil server.close_reason
    server.receive(retire(keylog, 0, packet_number: 1002), from: CLIENT, now:)
    assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, server.close_reason&.code

    server, keylog, now = issuing_server(Issuer.new)
    server.receive(retire(keylog, 9, packet_number: 1000), from: CLIENT, now:)
    assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, server.close_reason&.code
  end

  # A peer that retires each new ID straight away, a thousand times, piles
  # up no more than MAX_RETIRED IDs waiting three PTOs to be forgotten: the
  # oldest go at once, and the connection goes on (CVE-2024-1410).
  def test_retired_connection_ids_pile_up_to_a_bound
    issuer = Issuer.new
    server, keylog, now = issuing_server(issuer)
    [1, *(4..1002)].each_with_index do |sequence_number, index|
      server.receive(retire(keylog, sequence_number, packet_number: 1000 + index), from: CLIENT, now:)
    end
    assert_nil server.close_reason
    assert_equal 1000 - QUIC::IssuedConnectionIDs::MAX_RETIRED, issuer.forgotten.size
  end
end
