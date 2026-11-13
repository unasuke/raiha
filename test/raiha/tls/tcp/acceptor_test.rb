require "test_helper"
require "support/tcp_pair"

class RaihaNextTLSTCPAcceptorTest < Minitest::Test
  TLS = Raiha::TLS
  TCP = TLS::TCP
  Pair = NextTCPPair
  TLSPair = Pair::TLSPair
  NOW = Pair::NOW
  CHANGE_CIPHER_SPEC = "\x14\x03\x03\x00\x01\x01".b
  # A ClientHello in two records, as the server's Acceptor sees it.
  def test_accepts_a_client_hello
    record = Pair.take(Pair.client(server_name: "a.example"))
    hello = record.byteslice(5..).to_s
    acceptor = TCP::Acceptor.new
    acceptor.receive([22, 0x0303, 20].pack("Cnn") + hello.byteslice(0, 20).to_s, now: NOW)
    assert_nil acceptor.accepted
    acceptor.receive([22, 0x0303, hello.bytesize - 20].pack("Cnn") + hello.byteslice(20..).to_s, now: NOW)
    assert_equal hello, acceptor.accepted.bytes
    assert_equal "a.example", acceptor.accepted.info.server_name
    refute acceptor.failed?
  end

  def test_reject
    acceptor = TCP::Acceptor.new
    acceptor.receive(Pair.take(Pair.client(server_name: "c.example")), now: NOW)
    acceptor.reject(:unrecognized_name)
    assert_equal_bin "\x15\x03\x03\x00\x02\x02\x70".b, take(acceptor)
    assert acceptor.failed?
    assert_nil acceptor.accepted
  end

  def test_records_before_the_client_hello
    { CHANGE_CIPHER_SPEC => [:unexpected_message, :unexpected_record],
      "\x17\x03\x03\x00\x01x".b => [:unexpected_message, :unexpected_record],
      [22, 0x0303, (1 << 14) + 1].pack("Cnn") => [:record_overflow, :record_too_large] }.each do |bytes, (alert, reason)|
      acceptor = TCP::Acceptor.new
      acceptor.receive(bytes, now: NOW)
      assert_equal [alert, reason], [acceptor.alert, acceptor.reason], bytes.unpack1("H*")
      assert_equal 7, take(acceptor).bytesize
    end
  end

  # The client gave up: nothing goes back.
  def test_an_alert_from_the_client
    acceptor = TCP::Acceptor.new
    acceptor.receive("\x15\x03\x03\x00\x02\x02\x28".b, now: NOW)
    assert acceptor.failed?
    assert_equal [nil, :peer_alert], [acceptor.alert, acceptor.reason]
    assert_empty take(acceptor)
  end

  # The bytes held while the application decides are bounded.
  def test_too_much_after_the_client_hello
    acceptor = TCP::Acceptor.new
    acceptor.receive(Pair.take(Pair.client), now: NOW)
    acceptor.receive("\x17".b * TCP::Acceptor::MAX_HELD_BYTES, now: NOW)
    refute acceptor.failed?
    acceptor.receive("\x17".b, now: NOW)
    assert_equal [:unexpected_message, :too_much_data_before_accept], [acceptor.alert, acceptor.reason]
  end

  def test_hand_over_once
    acceptor = TCP::Acceptor.new
    assert_raises(TLS::UsageError) { acceptor.hand_over }
    acceptor.receive(Pair.take(Pair.client), now: NOW)
    accepted, record = acceptor.hand_over
    assert_equal acceptor.accepted, accepted
    assert_instance_of TLS::Record::Layer, record
    assert_raises(TLS::UsageError) { acceptor.hand_over }
  end

  Site = Data.define(:config, :keyring)

  def sites
    %w[a.example b.example].to_h do |name|
      config = TLSPair.server_config
      [name, Site.new(config:, keyring: TLSPair.server_keyring(config:, identities: [TLSPair.server_identity(names: ["DNS:#{name}"])]))]
    end
  end

  # The SNI path of a TCP server: the Config and Keyring by name.
  def test_connection_for_the_site_by_name
    sites = self.sites
    %w[a.example b.example].each do |name|
      client = Pair.client(server_name: name)
      acceptor = TCP::Acceptor.new
      acceptor.receive(Pair.take(client), now: NOW)
      site = sites.fetch(acceptor.accepted&.info&.server_name)
      server = TCP::Connection.server(config: site.config, keyring: site.keyring, acceptor:, now: NOW)
      Pair.pump(client, server)
      assert client.handshake_complete?, name
      client.write("hi")
      Pair.pump(client, server)
      assert_equal "hi", server.read(10)
    end
  end

  # What follows the ClientHello in the same segment, a ChangeCipherSpec
  # here, waits for the Connection, which reads it first.
  def test_the_connection_reads_what_was_held
    client = Pair.client
    acceptor = TCP::Acceptor.new
    acceptor.receive(Pair.take(client) + CHANGE_CIPHER_SPEC, now: NOW)
    config = TLSPair.server_config
    server = TCP::Connection.server(config:, keyring: TLSPair.server_keyring(config:), acceptor:, now: NOW)
    Pair.pump(client, server)
    assert server.handshake_complete?
    refute server.failed?
  end

  # A client's record_size_limit holds for the first flight too, which
  # goes out as the Connection is made.
  def test_record_size_limit_from_the_accepted_client_hello
    client = Pair.client(config: TLSPair.client_config(record_size_limit: 200))
    acceptor = TCP::Acceptor.new
    acceptor.receive(Pair.take(client), now: NOW)
    config = TLSPair.server_config
    server = TCP::Connection.server(config:, keyring: TLSPair.server_keyring(config:), acceptor:, now: NOW)
    assert Pair.records(Pair.take(server)).drop(2).all? { |_, length| length <= 200 + 16 }
  end

  def test_a_connection_needs_an_accepted_client_hello
    acceptor = TCP::Acceptor.new
    config = TLSPair.server_config
    keyring = TLSPair.server_keyring(config:)
    assert_raises(TLS::UsageError) { TCP::Connection.server(config:, keyring:, acceptor:, now: NOW) }
    acceptor.receive(Pair.take(Pair.client), now: NOW)
    TCP::Connection.server(config:, keyring:, acceptor:, now: NOW)
    assert_raises(TLS::UsageError) { TCP::Connection.server(config:, keyring:, acceptor:, now: NOW) }
  end

  def take(acceptor)
    taken = "".b
    acceptor.each_output { |bytes| taken << bytes }
    taken
  end
end
