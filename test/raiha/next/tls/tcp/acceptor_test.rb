require "raiha/next/test_helper"
require "raiha/next/support/tcp_pair"

class RaihaNextTLSTCPAcceptorTest < Minitest::Test
  TLS = Raiha::Next::TLS
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

  def take(acceptor)
    taken = "".b
    acceptor.each_output { |bytes| taken << bytes }
    taken
  end
end
