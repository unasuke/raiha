require "test_helper"
require "support/tcp_pair"
require "stringio"

class RaihaTLSTCPConnectionTest < Minitest::Test
  TLS = Raiha::TLS
  TCP = TLS::TCP
  Pair = TCPPair
  NOW = Pair::NOW

  def failed(connection) = Pair.events(connection).grep(TLS::Event::Failed).first

  def test_handshake_and_application_data
    pair = Pair.connect
    assert pair.client.handshake_complete?
    assert pair.server.handshake_complete?
    assert_equal 3, pair.client.write("abc")
    assert_equal 5, pair.server.write("hello")
    Pair.pump(pair.client, pair.server)
    assert_equal ["abc", "hello"], [pair.server.read(100), pair.client.read(100)]
    assert_equal "", pair.client.read(100)
    [pair.client, pair.server].each do |connection|
      assert_instance_of TLS::Event::HandshakeComplete, Pair.events(connection).first
    end
  end

  def test_bytes_one_at_a_time
    client, server = Pair.client, Pair.server
    loop do
      sent = Pair.take(client)
      sent.each_char { |byte| server.receive(byte, now: NOW) }
      answer = Pair.take(server)
      answer.each_char { |byte| client.receive(byte, now: NOW) }
      break if sent.empty? && answer.empty?
    end
    assert client.handshake_complete?
    assert server.handshake_complete?
  end

  # The first flight of each side as records: a server's handshake messages
  # of one epoch go in one record, and each side sends one ChangeCipherSpec
  # (RFC 9846 "Middlebox Compatibility Mode").
  def test_records_of_the_handshake
    client, server = Pair.client, Pair.server
    client_hello = Pair.take(client)
    assert_equal [22], Pair.records(client_hello).map(&:first)
    server.receive(client_hello, now: NOW)
    first_flight = Pair.take(server)
    assert_equal [22, 20, 23], Pair.records(first_flight).map(&:first)
    client.receive(first_flight, now: NOW)
    assert_equal [20, 23], Pair.records(Pair.take(client)).map(&:first)
  end

  # Held until the handshake completes, and only up to the limit.
  def test_writes_before_the_handshake
    client, server = Pair.client, Pair.server
    big = "x" * (TCP::Connection::WRITE_BUFFER_LIMIT + 100)
    taken = client.write(big)
    assert_operator taken, :<, TCP::Connection::WRITE_BUFFER_LIMIT
    assert_equal 0, client.write("more")
    Pair.pump(client, server)
    assert_equal big.byteslice(0, taken), server.read(1 << 20)
    assert_equal 4, client.write("more")
  end

  # RFC 8449: each side's protected records keep to the other's limit,
  # the server's first flight included.
  def test_record_size_limit
    client = Pair.client(config: Pair::TLSPair.client_config(record_size_limit: 200))
    server = Pair.server(config: Pair::TLSPair.server_config(record_size_limit: 300))
    server.receive(Pair.take(client), now: NOW)
    flight = Pair.records(Pair.take(server))
    assert_operator flight.size, :>, 3
    assert flight.drop(2).all? { |_, length| length <= 200 + 16 }, flight.inspect

    pair = Pair.connect(client: Pair.client(config: Pair::TLSPair.client_config(record_size_limit: 200)),
      server: Pair.server(config: Pair::TLSPair.server_config(record_size_limit: 300)))
    pair.client.write("c" * 1000)
    pair.server.write("s" * 1000)
    to_server = Pair.records(Pair.take(pair.client))
    to_client = Pair.records(Pair.take(pair.server))
    assert_equal [299 + 1 + 16] * 3 + [103 + 1 + 16], to_server.map(&:last)
    assert_equal [199 + 1 + 16] * 5 + [5 + 1 + 16], to_client.map(&:last)
  end

  def test_read_takes_at_most_max_bytes
    pair = Pair.connect
    pair.server.write("abcdef")
    Pair.pump(pair.client, pair.server)
    assert_equal ["ab", "cde", "f", ""], [2, 3, 10, 10].map { |n| pair.client.read(n) }
  end

  def test_a_record_that_does_not_open
    client, server = Pair.client, Pair.server
    server.receive(Pair.take(client), now: NOW)
    flight = Pair.take(server)
    flight.setbyte(-1, flight.getbyte(-1) ^ 1)
    client.receive(flight, now: NOW)
    assert client.failed?
    assert_equal TLS::Event::Failed.new(alert: :bad_record_mac, reason: :bad_record_mac), failed(client)
    # The alert goes under the epoch the server reads, :handshake.
    assert_equal [[20, 1], [23, 19]], Pair.records(Pair.take(client))
    assert_nil client.receive("anything", now: NOW)
    assert_raises(TLS::UsageError) { client.write("x") }
    assert_raises(TLS::UsageError) { client.read(1) }
  end

  # Any alert from the peer ends the connection, and none goes back.
  def test_an_alert_from_the_peer
    client = Pair.client
    Pair.take(client)
    client.receive("\x15\x03\x03\x00\x02\x02\x28".b, now: NOW)
    assert client.failed?
    assert_equal [TCP::Event::PeerAlert.new(level: 2, description: 40)], Pair.events(client)
    assert_empty Pair.take(client)
  end

  def test_a_malformed_alert
    client = Pair.client
    Pair.take(client)
    client.receive("\x15\x03\x03\x00\x03\x02\x28\x00".b, now: NOW)
    assert_equal TLS::Event::Failed.new(alert: :decode_error, reason: :malformed_alert), failed(client)
  end

  # The Machine's failure: its alert, in the clear before any keys.
  def test_a_failure_in_the_handshake
    client = Pair.client(config: Pair::TLSPair.client_config(alpn: ["h2"]))
    server = Pair.server(config: Pair::TLSPair.server_config(alpn: ["h3"]))
    server.receive(Pair.take(client), now: NOW)
    assert server.failed?
    alert = Pair.take(server)
    assert_equal_bin "\x15\x03\x03\x00\x02\x02\x78".b, alert
    client.receive(alert, now: NOW)
    assert_equal [TCP::Event::PeerAlert.new(level: 2, description: 120)], Pair.events(client)
  end

  # A ChangeCipherSpec only once a ClientHello is in, and never inside a
  # message split across records.
  def test_change_cipher_spec_placement
    server = Pair.server
    server.receive("\x14\x03\x03\x00\x01\x01".b, now: NOW)
    assert_equal TLS::Event::Failed.new(alert: :unexpected_message, reason: :unexpected_change_cipher_spec), failed(server)

    client, server = Pair.client, Pair.server
    hello = Pair.take(client).byteslice(5..).to_s
    split = [hello.byteslice(0, 10).to_s, hello.byteslice(10..).to_s].map { |part| [22, 0x0303, part.bytesize].pack("Cnn") + part }
    server.receive(split[0] + "\x14\x03\x03\x00\x01\x01".b + split[1], now: NOW)
    assert_equal TLS::Event::Failed.new(alert: :unexpected_message, reason: :interleaved_record), failed(server)
  end

  # Application data under the handshake keys: the client's Finished has
  # not come yet.
  def test_application_data_before_the_handshake_completes
    keylog = StringIO.new
    client, server = Pair.client(keylog:), Pair.server
    server.receive(Pair.take(client), now: NOW)
    client.receive(Pair.take(server), now: NOW)
    secret = [keylog.string.lines.grep(/\ACLIENT_HANDSHAKE_TRAFFIC_SECRET/).first.split.last].pack("H*")
    forged = TLS::Record::Protection.new(secret:, cipher_suite: TLS::CipherSuite::TLS_AES_128_GCM_SHA256).seal("early\x17".b)
    server.receive(forged, now: NOW)
    assert_equal TLS::Event::Failed.new(alert: :unexpected_message, reason: :application_data_before_handshake), failed(server)
  end

  def test_only_with_a_record_layer
    config = Pair::TLSPair.client_config(profile: TLS::Profile::QUIC)
    assert_raises(ArgumentError) { Pair.client(config:) }
  end
end
