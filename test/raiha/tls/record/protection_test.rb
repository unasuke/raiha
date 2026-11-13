require "test_helper"
require "raiha/tls"
require "raiha/tls/test"

# Record protection against every protected record of RFC 8448 section 3.
class RaihaNextTLSRecordProtectionTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Protection = TLS::Record::Protection
  RFC8448 = TLS::Test::RFC8448::Simple1RTT
  SUITE = TLS::CipherSuite::TLS_AES_128_GCM_SHA256

  HANDSHAKE = "\x16".b
  APPLICATION_DATA = "\x17".b
  CLOSE_NOTIFY = "\x01\x00\x15".b

  # [traffic secret, [[TLSInnerPlaintext, record], ...]] in sequence order.
  def flights
    {
      server_handshake: [RFC8448::SERVER_HANDSHAKE_TRAFFIC_SECRET, [
        [RFC8448::ENCRYPTED_EXTENSIONS + RFC8448::CERTIFICATE + RFC8448::CERTIFICATE_VERIFY + RFC8448::SERVER_FINISHED + HANDSHAKE,
          RFC8448::SERVER_HANDSHAKE_RECORD]
      ]],
      client_handshake: [RFC8448::CLIENT_HANDSHAKE_TRAFFIC_SECRET, [[RFC8448::CLIENT_FINISHED + HANDSHAKE, RFC8448::CLIENT_FINISHED_RECORD]]],
      server_application: [RFC8448::SERVER_APPLICATION_TRAFFIC_SECRET_0, [
        [RFC8448::NEW_SESSION_TICKET + HANDSHAKE, RFC8448::NEW_SESSION_TICKET_RECORD],
        [RFC8448::APPLICATION_DATA + APPLICATION_DATA, RFC8448::SERVER_APPLICATION_DATA_RECORD],
        [CLOSE_NOTIFY, RFC8448::SERVER_ALERT_RECORD]
      ]],
      client_application: [RFC8448::CLIENT_APPLICATION_TRAFFIC_SECRET_0, [
        [RFC8448::APPLICATION_DATA + APPLICATION_DATA, RFC8448::CLIENT_APPLICATION_DATA_RECORD],
        [CLOSE_NOTIFY, RFC8448::CLIENT_ALERT_RECORD]
      ]]
    }
  end

  def test_seal_reproduces_each_record
    flights.each_value do |secret, records|
      protection = Protection.new(secret:, cipher_suite: SUITE)
      records.each { |inner, record| assert_equal_bin record, protection.seal(inner) }
      assert_equal records.size, protection.sequence_number
    end
  end

  def test_open_recovers_each_inner_plaintext
    flights.each_value do |secret, records|
      protection = Protection.new(secret:, cipher_suite: SUITE)
      records.each do |inner, record|
        assert_equal_bin inner, protection.open(record.byteslice(0, 5).to_s, record.byteslice(5..).to_s)
      end
    end
  end

  # The nonce follows the sequence number, so a record opened out of turn
  # does not authenticate; it is not counted, and the record in turn still
  # opens.
  def test_a_skipped_record_does_not_open
    _, records = flights.fetch(:server_application)
    protection = Protection.new(secret: RFC8448::SERVER_APPLICATION_TRAFFIC_SECRET_0, cipher_suite: SUITE)
    first, second = records.fetch(0).last, records.fetch(1).last
    assert_nil protection.open(second.byteslice(0, 5).to_s, second.byteslice(5..).to_s)
    assert_equal 0, protection.sequence_number
    assert protection.open(first.byteslice(0, 5).to_s, first.byteslice(5..).to_s)
    assert_equal 1, protection.sequence_number
  end

  # The header is the additional data: a changed length byte fails too.
  def test_the_header_is_authenticated
    protection = Protection.new(secret: RFC8448::CLIENT_HANDSHAKE_TRAFFIC_SECRET, cipher_suite: SUITE)
    header = RFC8448::CLIENT_FINISHED_RECORD.byteslice(0, 5).to_s.dup
    header.setbyte(2, 0x01)
    assert_nil protection.open(header, RFC8448::CLIENT_FINISHED_RECORD.byteslice(5..).to_s)
  end

  def test_secrets_stay_out_of_inspect
    protection = Protection.new(secret: RFC8448::CLIENT_HANDSHAKE_TRAFFIC_SECRET, cipher_suite: SUITE)
    refute_match(/@iv|@aead|@key/, protection.inspect)
    protection.discard!
    assert_empty protection.instance_variable_get(:@iv)
  end
end
