require "test_helper"
require "raiha/tls/test"

class RaihaNextTLSHandshakeReassemblerTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Reassembler = TLS::Handshake::Reassembler
  RFC8448 = TLS::Test::RFC8448::Simple1RTT

  # Certificate, CertificateRequest and CompressedCertificate get 256 KiB,
  # every other type 16 KiB.
  LIMITS = ->(msg_type) { [11, 13, 25].include?(msg_type) ? 256 * 1024 : 16 * 1024 }

  def reassembler(*types)
    r = Reassembler.new(limits: LIMITS)
    r.expect(Set[*types])
    r
  end

  def messages(r)
    list = []
    status = r.each_message { |type, body| list << [type, body] }
    [status, list]
  end

  def test_one_message
    r = reassembler(1)
    assert_equal :ok, r << RFC8448::CLIENT_HELLO
    assert_equal [:ok, [[1, RFC8448::CLIENT_HELLO.byteslice(4..)]]], messages(r)
    refute r.pending?
  end

  def test_message_split_into_single_bytes
    r = reassembler(1)
    RFC8448::CLIENT_HELLO.each_byte.with_index do |byte, i|
      assert_equal :ok, r << byte.chr.b
      assert_equal [:ok, []], messages(r) unless i == RFC8448::CLIENT_HELLO.bytesize - 1
    end
    assert_equal [:ok, [[1, RFC8448::CLIENT_HELLO.byteslice(4..)]]], messages(r)
  end

  # The server's flight arrives in one piece while the state machine expects
  # one message at a time, changing what it expects after each.
  def test_several_messages_with_expectations_changing_between_them
    flight = RFC8448::ENCRYPTED_EXTENSIONS + RFC8448::CERTIFICATE + RFC8448::CERTIFICATE_VERIFY + RFC8448::SERVER_FINISHED
    r = reassembler(8)
    assert_equal :ok, r << flight
    following = { 8 => 11, 11 => 15, 15 => 20, 20 => 4 }
    seen = []
    status = r.each_message do |type, body|
      seen << [type, body.bytesize]
      r.expect(Set[following.fetch(type)])
    end
    assert_equal :ok, status
    assert_equal [[8, 36], [11, 441], [15, 132], [20, 32]], seen
    refute r.pending?
  end

  def test_unexpected_type_is_rejected_from_its_header
    r = reassembler(2)
    assert_equal :unexpected, r << "\x0b\x03\xff\xff".b
    assert_equal [:unexpected, []], messages(r)
  end

  def test_unknown_type_is_unexpected
    r = reassembler(1, 2)
    assert_equal :unexpected, r << "\x63\x00\x00\x00".b
  end

  def test_next_message_checked_against_the_updated_expectation
    r = reassembler(8)
    assert_equal :ok, r << RFC8448::ENCRYPTED_EXTENSIONS + RFC8448::SERVER_FINISHED
    seen = []
    status = r.each_message do |type, _body|
      seen << type
      r.expect(Set[11, 13])
    end
    assert_equal :unexpected, status
    assert_equal [8], seen
  end

  def test_overflow_is_rejected_from_the_header
    r = reassembler(1)
    assert_equal :overflow, r << "\x01\x00\x40\x01".b
    assert_equal :overflow, r << "\x00".b * 100
    assert_equal [:overflow, []], messages(r)
  end

  def test_limits_are_per_type
    r = reassembler(11)
    assert_equal :ok, r << "\x0b\x04\x00\x00".b
    r = reassembler(11)
    assert_equal :overflow, r << "\x0b\x04\x00\x01".b
    r = reassembler(8)
    assert_equal :ok, r << "\x08\x00\x40\x00".b
  end

  def test_pending_while_a_message_is_incomplete
    r = reassembler(1)
    r << RFC8448::CLIENT_HELLO.byteslice(0, 10)
    assert_equal [:ok, []], messages(r)
    assert r.pending?
    r << RFC8448::CLIENT_HELLO.byteslice(10..)
    assert r.pending?
    messages(r)
    refute r.pending?
  end

  def test_body_is_frozen_binary
    r = reassembler(20)
    r << RFC8448::SERVER_FINISHED
    r.each_message do |_type, body|
      assert body.frozen?
      assert_equal Encoding::BINARY, body.encoding
    end
  end
end
