require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# What the network sends never raises out of `Connection#receive` or
# `Endpoint#receive`. The inputs are random bytes, real datagrams with a
# byte changed, and packets that open, sealed with the keys of their level,
# whose frames are random bytes, frames of random types with random bodies,
# or real frames with random values: so that what comes after the
# decryption is reached too. RAIHA_FUZZ_ITERATIONS (default 300) and
# RAIHA_FUZZ_SEED change the number of inputs to each target and the seed.
class RaihaNextQUICReceiveFuzzTest < Minitest::Test
  include NextQUICPair

  ITERATIONS = Integer(ENV.fetch("RAIHA_FUZZ_ITERATIONS", "300"))
  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "9000"))
  FRAME_TYPES = [*0x00..0x1e, 0x30, 0x31].freeze

  def random_frames(rng)
    case rng.rand(3)
    when 0 then rng.bytes(rng.rand(1..60))
    when 1 then Array.new(rng.rand(1..4)) { [FRAME_TYPES.sample(random: rng)].pack("C") + rng.bytes(rng.rand(0..20)) }.join
    else
      frames = Array.new(rng.rand(1..4)) do
        case rng.rand(5)
        when 0 then QUIC::Wire::Frame::Ping.new
        when 1
          largest = rng.rand(0..40)
          QUIC::Wire::Frame::Ack.new(ranges: [rng.rand(0..largest)..largest], delay: rng.rand * 0.1)
        when 2 then QUIC::Wire::Frame::Crypto.new(offset: rng.rand(0..20_000), data: rng.bytes(rng.rand(1..40)))
        when 3 then QUIC::Wire::Frame::HandshakeDone.new
        else QUIC::Wire::Frame::ConnectionClose.new(code: rng.rand(0..0x200), frame_type: 0, reason: rng.bytes(rng.rand(0..10)), application: false)
        end
      end
      QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3)
    end
  end

  # A packet of `header` with `payload`, sealed with `keys`, padded to
  # `size` bytes.
  def packet(header, payload, keys, packet_number:, size: 0)
    payload = payload.ljust(20, "\0".b)
    sealed = QUIC::Wire::Packet.seal(header, packet_number:, packet_number_length: 2, payload:, keys:)
    return sealed if sealed.bytesize >= size
    QUIC::Wire::Packet.seal(header, packet_number:, packet_number_length: 2, payload: payload.ljust(payload.bytesize + size - sealed.bytesize, "\0".b), keys:)
  end

  # Runs the block ITERATIONS times; it gives the input it is about to
  # apply to `take`, and an exception from that fails with the input.
  def run_fuzz(label)
    rng = Random.new(SEED)
    ITERATIONS.times do |i|
      input = nil
      take = ->(datagram) { input = datagram }
      begin
        yield rng, take
      rescue => e
        flunk "#{label} seed=#{SEED} iteration=#{i}: #{e.class}: #{e.message}\ninput=#{input&.unpack1("H*")}\n#{e.backtrace.first(8).join("\n")}"
      end
    end
  end

  # A server takes any Initial of a client: the first opens and starts the
  # handshake, those after it carry random frames.
  def test_a_server_takes_any_initial
    server = nil
    dcid = nil
    number = 0
    run_fuzz("server Initial") do |rng, take|
      if server.nil? || server.closing? || server.draining? || server.closed?
        server = server_connection
        dcid = rng.bytes(8)
        number = 0
      end
      header = QUIC::Wire::LongHeader.new(type: :initial, version: QUIC::Version::V1, dcid:, scid: "c".b * 8)
      keys = QUIC::Crypto::Initial.derive(dcid:, version: QUIC::Version::V1).client
      take.(datagram = packet(header, random_frames(rng), keys, packet_number: number += 1, size: 1200))
      server.receive(datagram, from: CLIENT, now: 0.0)
      server.transmits(now: 0.0)
    end
  end

  # A client mid-handshake takes any Initial of the server.
  def test_a_client_takes_any_initial
    client = nil
    first = nil
    number = 0
    run_fuzz("client Initial") do |rng, take|
      if client.nil? || client.closing? || client.draining? || client.closed?
        client = client_connection(random: Random.new(rng.rand(1 << 32)))
        first = QUIC::Wire::Packet.parse(client.transmits(now: 0.0).first.payload, dcid_length: 8).header
        number = 0
      end
      header = QUIC::Wire::LongHeader.new(type: :initial, version: QUIC::Version::V1, dcid: first.scid, scid: "s".b * 8)
      keys = QUIC::Crypto::Initial.derive(dcid: first.dcid, version: QUIC::Version::V1).server
      take.(datagram = packet(header, random_frames(rng), keys, packet_number: number += 1))
      client.receive(datagram, from: SERVER, now: 0.0)
      client.transmits(now: 0.0)
    end
  end

  # A server done with the handshake takes any 1-RTT packet of the client,
  # sealed with the client's keys from its key log.
  def test_a_server_takes_any_one_rtt_packet
    server = nil
    keylog = nil
    server_id = nil
    number = 1000
    run_fuzz("server 1-RTT") do |rng, take|
      if server.nil? || server.closing? || server.draining? || server.closed?
        keylog = Keylog.new
        client = client_connection(keylog:)
        server = server_connection
        first = client.transmits(now: 0.0).first.payload
        server.receive(first, from: CLIENT, now: 0.0)
        reply = server.transmits(now: 0.0)
        server_id = QUIC::Wire::Packet.parse(reply.first.payload, dcid_length: 8).header.scid
        reply.each { client.receive(_1.payload, from: SERVER, now: 0.0) }
        handshake(client, server)
        number = 1000
      end
      take.(datagram = client_one_rtt(keylog, dcid: server_id, payload: random_frames(rng), packet_number: number += 1))
      server.receive(datagram, from: CLIENT, now: 1.0)
      server.transmits(now: 1.0)
    end
  end

  # A server's Endpoint takes any datagram: random bytes, and real
  # datagrams of a handshake with a byte changed.
  def test_an_endpoint_takes_any_datagram
    datagrams = []
    client = client_connection
    server = server_connection
    now = 0.0
    10.times do
      client.transmits(now:).each { datagrams << _1.payload; server.receive(_1.payload, from: CLIENT, now:) }
      server.transmits(now:).each { datagrams << _1.payload; client.receive(_1.payload, from: SERVER, now:) }
      now += 0.001
    end
    endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: Random.new(SEED), time: NOW, now: 0.0)
    run_fuzz("endpoint") do |rng, take|
      datagram =
        if rng.rand(2).zero?
          rng.bytes(rng.rand(1..1300))
        else
          datagrams.sample(random: rng).dup.tap { _1.setbyte(rng.rand(_1.bytesize), rng.rand(256)) }
        end
      take.(datagram)
      route = endpoint.receive(datagram, from: CLIENT, to: SERVER, now: 0.0)
      endpoint.admit(route.handle, now: 0.0) if route.is_a?(QUIC::Route::Incoming)
      endpoint.each_transmit(now: 0.0) { nil }
    end
  end
end
