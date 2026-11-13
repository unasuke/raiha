require "test_helper"
require "support/quic_transfer"

# A connection with the Config's max_transmit_size puts the datagrams of
# one size it sends in one Transmit, for GSO; without, a datagram each.
class RaihaNextQUICConnectionTransmitSizeTest < Minitest::Test
  include NextQUICTransfer

  # The datagrams of `transmit`, cut at its segment size.
  def datagrams(transmit)
    size = transmit.segment_size or return [transmit.payload]
    transmit.payload.bytes.each_slice(size).map { _1.pack("C*") }
  end

  # A server of `config` that took a request on stream 0 and wrote `size`
  # bytes back, the client, and the time.
  def responding(size, config:)
    client = client_connection
    server = server_connection(config:)
    now = handshake(client, server)
    [client, server].each { |connection| connection.each_event { nil } }
    stream = client.open_stream
    client.stream_write(stream, "GET", fin: true)
    client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
    server.stream_write(stream, "x".b * size, fin: true)
    [client, server, now]
  end

  # Ten datagrams of 1,200 bytes fit in 12,000: a burst of the initial
  # window is one or two Transmits, each of datagrams of one size but the
  # last, and the client reads what they carry.
  def test_datagrams_of_one_size_in_a_transmit
    client, server, now = responding(30_000, config: QUIC::Config.new(max_transmit_size: 12_000))
    transmits = server.transmits(now:)
    assert transmits.any? { (_1.segment_size || 0) > 0 }
    transmits.each do |transmit|
      assert_operator transmit.payload.bytesize, :<=, 12_000
      sizes = datagrams(transmit).map(&:bytesize)
      assert_equal [sizes.first] * (sizes.size - 1), sizes[0...-1]
      assert_operator sizes.last, :<=, sizes.first
    end
    transmits.flat_map { datagrams(_1) }.each { |datagram| client.receive(datagram, from: SERVER, now:) }
    assert_operator client.stream_read(0, 100_000).bytesize, :>, 10_000
  end

  # A probe of the path MTU, which the server sends once the handshake is
  # confirmed, goes in a Transmit of its own, though what goes after it
  # would go in with it as smaller datagrams.
  def test_a_probe_of_the_mtu_alone
    client = client_connection
    server = server_connection(config: QUIC::Config.new(max_transmit_size: 12_000))
    transmits = []
    now = 0.0
    until server.handshake_confirmed? && transmits.any? { _1.payload.bytesize == 1472 }
      flunk "no probe" if now > 0.01
      client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now:) }
      server.transmits(now:).each { transmits << _1 }.each { client.receive(_1.payload, from: SERVER, now:) }
      now += 0.001
    end
    assert_nil transmits.find { _1.payload.bytesize == 1472 }.segment_size
    refute transmits.any? { _1.segment_size == 1472 }
  end

  # A datagram each, as before, without it.
  def test_a_datagram_each_without
    _client, server, now = responding(30_000, config: QUIC::Config.new)
    transmits = server.transmits(now:)
    assert_operator transmits.size, :>, 1
    assert transmits.all? { _1.segment_size.nil? }
  end

  # Over a bottleneck, the network cutting each Transmit at its segment
  # size, a download goes as it goes with a datagram each.
  def test_a_download_in_transmits_of_several
    path = Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.01, queue: 100_000)
    net, _client, _server, reads = download(1_000_000, model: path, server_config: QUIC::Config.new(max_transmit_size: 65_507))
    assert net.run_until(within: 30.0) { reads.last&.last == 1_000_000 }
  end
end
