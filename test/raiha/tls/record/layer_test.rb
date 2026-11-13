require "test_helper"
require "raiha/tls"
require "raiha/tls/test"

class RaihaTLSRecordLayerTest < Minitest::Test
  TLS = Raiha::TLS
  Record = TLS::Record
  RFC8448 = TLS::Test::RFC8448::Simple1RTT
  SUITE = TLS::CipherSuite::TLS_AES_128_GCM_SHA256
  SECRET = RFC8448::CLIENT_HANDSHAKE_TRAFFIC_SECRET

  def layer = Record::Layer.new(profile: TLS::Profile::TCP)

  def plaintext_record(type, payload) = [type, 0x0303, payload.bytesize].pack("Cnn") + payload

  def server_hello_record = plaintext_record(22, RFC8448::SERVER_HELLO)

  def plaintext(content_type, payload) = Record::Plaintext.new(content_type:, payload:)

  def failure(alert, reason) = Record::Failure.new(alert:, reason:)

  # A layer reading under SECRET, and a Protection that writes for it.
  def reader_and_sealer
    reader = layer
    reader.install(direction: :read, epoch: :handshake, secret: SECRET, cipher_suite: SUITE)
    [reader, Record::Protection.new(secret: SECRET, cipher_suite: SUITE)]
  end

  # RFC 8448 section 3 as the client reads it: the ServerHello and the
  # protected flight in one segment, the read epoch moving between them.
  def test_rfc8448_client_reads_the_server
    rec = layer
    rec << server_hello_record + RFC8448::SERVER_HANDSHAKE_RECORD
    assert_equal plaintext(:handshake, RFC8448::SERVER_HELLO), rec.read(epoch: :initial)
    rec.install(direction: :read, epoch: :handshake, secret: RFC8448::SERVER_HANDSHAKE_TRAFFIC_SECRET, cipher_suite: SUITE)
    flight = RFC8448::ENCRYPTED_EXTENSIONS + RFC8448::CERTIFICATE + RFC8448::CERTIFICATE_VERIFY + RFC8448::SERVER_FINISHED
    assert_equal plaintext(:handshake, flight), rec.read(epoch: :handshake)
    assert_nil rec.read(epoch: :handshake)
    rec.install(direction: :read, epoch: :application, secret: RFC8448::SERVER_APPLICATION_TRAFFIC_SECRET_0, cipher_suite: SUITE)
    rec << RFC8448::NEW_SESSION_TICKET_RECORD + RFC8448::SERVER_APPLICATION_DATA_RECORD + RFC8448::SERVER_ALERT_RECORD
    assert_equal [plaintext(:handshake, RFC8448::NEW_SESSION_TICKET), plaintext(:application_data, RFC8448::APPLICATION_DATA),
      plaintext(:alert, "\x01\x00".b)], Array.new(3) { rec.read(epoch: :application) }
    assert_equal 0, rec.pending_bytes
  end

  def test_rfc8448_client_writes
    rec = layer
    rec.install(direction: :write, epoch: :handshake, secret: RFC8448::CLIENT_HANDSHAKE_TRAFFIC_SECRET, cipher_suite: SUITE)
    assert_equal_bin RFC8448::CLIENT_FINISHED_RECORD, rec.write(content_type: :handshake, payload: RFC8448::CLIENT_FINISHED, epoch: :handshake)
    rec.install(direction: :write, epoch: :application, secret: RFC8448::CLIENT_APPLICATION_TRAFFIC_SECRET_0, cipher_suite: SUITE)
    assert_equal_bin RFC8448::CLIENT_APPLICATION_DATA_RECORD + RFC8448::CLIENT_ALERT_RECORD,
      rec.write(content_type: :application_data, payload: RFC8448::APPLICATION_DATA, epoch: :application) +
        rec.write(content_type: :alert, payload: "\x01\x00".b, epoch: :application)
    assert_equal 2, rec.records_written(:application)
    assert_equal_bin server_hello_record, layer.write(content_type: :handshake, payload: RFC8448::SERVER_HELLO, epoch: :initial)
  end

  def test_a_record_split_anywhere
    rec = layer
    bytes = server_hello_record
    bytes.each_char.with_index do |byte, i|
      assert_nil rec.read(epoch: :initial)
      rec << byte
      assert_equal i + 1, rec.pending_bytes
    end
    assert_equal plaintext(:handshake, RFC8448::SERVER_HELLO), rec.read(epoch: :initial)
  end

  def test_fragments_to_the_limit
    writer = layer
    writer.install(direction: :write, epoch: :application, secret: SECRET, cipher_suite: SUITE)
    reader, = reader_and_sealer
    reader.install(direction: :read, epoch: :application, secret: SECRET, cipher_suite: SUITE)
    data = Random.new(8449).bytes(40_000)
    reader << writer.write(content_type: :application_data, payload: data, epoch: :application)
    sizes = []
    while (record = reader.read(epoch: :application))
      sizes << record.payload.bytesize
    end
    assert_equal [16_384, 16_384, 7_232], sizes
    assert_equal [16_384, 16_384], [writer.fragment_size(:initial), writer.fragment_size(:application)]
    writer.limit_sizes(send: 1000)
    assert_equal [16_384, 999], [writer.fragment_size(:initial), writer.fragment_size(:application)]
    reader << writer.write(content_type: :application_data, payload: data.byteslice(0, 2000).to_s, epoch: :application)
    assert_equal [999, 999, 2], Array.new(3) { reader.read(epoch: :application)&.payload&.bytesize }
    # A limit above the default is the default: three records again, each
    # with its header, content type and tag.
    writer.limit_sizes(send: 1 << 20)
    assert_equal data.bytesize + 3 * (5 + 1 + 16), writer.write(content_type: :application_data, payload: data, epoch: :application).bytesize
  end

  def test_unprotected_epoch_rules
    {
      plaintext_record(23, "x") => failure(:unexpected_message, :unexpected_record),
      plaintext_record(24, "x") => failure(:unexpected_message, :unexpected_record),
      plaintext_record(22, "") => failure(:unexpected_message, :empty_handshake_record),
      plaintext_record(21, "") => failure(:unexpected_message, :empty_alert_record),
      plaintext_record(22, "x" * (Record::MAX_PLAINTEXT + 1)) => failure(:record_overflow, :record_too_large),
      plaintext_record(20, "\x01") => plaintext(:change_cipher_spec, "\x01".b),
      plaintext_record(21, "\x02\x28") => plaintext(:alert, "\x02\x28".b)
    }.each do |bytes, expected|
      rec = layer
      rec << bytes
      assert_equal expected, rec.read(epoch: :initial), bytes.byteslice(0, 8).unpack1("H*")
    end
  end

  # A length past 2^14 + 256 fails as soon as the header is in, and past
  # 2^14 for a record that is never protected.
  def test_overlong_header
    [[23, Record::MAX_PLAINTEXT + Record::MAX_EXPANSION + 1], [22, Record::MAX_PLAINTEXT + 1], [21, Record::MAX_PLAINTEXT + 1]].each do |type, length|
      [:initial, :handshake].each do |epoch|
        rec = layer
        rec << [type, 0x0303, length].pack("Cnn")
        assert_equal failure(:record_overflow, :record_too_large), rec.read(epoch:), [type, epoch].inspect
      end
    end
    rec = layer
    rec << [23, 0x0303, Record::MAX_PLAINTEXT + Record::MAX_EXPANSION].pack("Cnn")
    assert_nil rec.read(epoch: :initial)
  end

  # A header of a type no record has fails at once, before the length it
  # gives is in: an SSL 2.0 ClientHello, whose bytes read as a length of
  # 772 here.
  def test_a_type_no_record_has
    layer = Record::Layer.new(profile: TLS::Profile::TCP)
    layer << "\x80\x2e\x01\x03\x04".b
    assert_equal failure(:unexpected_message, :unexpected_record), layer.read(epoch: :initial)
  end

  def test_protected_epoch_rules
    reader, sealer = reader_and_sealer
    cases = {
      sealer.seal("hello\x16\x00\x00\x00".b) => plaintext(:handshake, "hello".b),
      sealer.seal("\x17".b) => plaintext(:application_data, "".b),
      sealer.seal("\x16".b) => failure(:unexpected_message, :empty_handshake_record),
      sealer.seal("\x15\x00\x00".b) => failure(:unexpected_message, :empty_alert_record),
      sealer.seal("\x01\x14".b) => failure(:unexpected_message, :unexpected_record),
      sealer.seal("\x01\x2a".b) => failure(:unexpected_message, :unexpected_record),
      sealer.seal("\x00\x00".b) => failure(:unexpected_message, :no_content_type),
      plaintext_record(22, "x") => failure(:unexpected_message, :unprotected_record),
      plaintext_record(20, "\x01") => plaintext(:change_cipher_spec, "\x01".b),
      plaintext_record(21, "\x02\x28") => plaintext(:alert, "\x02\x28".b)
    }
    cases.each do |bytes, expected|
      reader << bytes
      assert_equal expected, reader.read(epoch: :handshake), bytes.byteslice(0, 8).unpack1("H*")
    end
  end

  # Only the one byte 0x01, and only before the peer's Finished, that is,
  # before the :application read keys.
  def test_change_cipher_spec_rules
    reader, = reader_and_sealer
    reader.install(direction: :read, epoch: :application, secret: SECRET, cipher_suite: SUITE)
    unexpected = failure(:unexpected_message, :unexpected_change_cipher_spec)
    { :initial => "\x01", :handshake => "\x01" }.each do |epoch, payload|
      reader << plaintext_record(20, payload)
      assert_equal plaintext(:change_cipher_spec, "\x01".b), reader.read(epoch:)
    end
    [[:initial, "\x02"], [:handshake, "\x01\x01"], [:initial, ""], [:application, "\x01"]].each do |epoch, payload|
      reader << plaintext_record(20, payload)
      assert_equal unexpected, reader.read(epoch:), [epoch, payload].inspect
    end
  end

  # After the handshake keys, an alert in the clear is a protocol error.
  def test_unprotected_alert_under_application_keys
    rec = layer
    rec.install(direction: :read, epoch: :application, secret: SECRET, cipher_suite: SUITE)
    rec << plaintext_record(21, "\x02\x28")
    assert_equal failure(:unexpected_message, :unprotected_record), rec.read(epoch: :application)
  end

  def test_bad_record_mac
    reader, sealer = reader_and_sealer
    record = sealer.seal("hello\x16".b)
    record.setbyte(-1, record.getbyte(-1) ^ 0x80)
    reader << record
    assert_equal failure(:bad_record_mac, :bad_record_mac), reader.read(epoch: :handshake)
  end

  # RFC 9846 "Early Data Indication": a server that did not take 0-RTT
  # skips the records that do not open under the handshake key, up to its
  # limit, until one does.
  def test_skipping_rejected_0rtt_under_the_handshake_key
    reader, sealer = reader_and_sealer
    early = Record::Protection.new(secret: RFC8448::SERVER_HANDSHAKE_TRAFFIC_SECRET, cipher_suite: SUITE)
    reader << early.seal(("a" * 100 + "\x17").b) << early.seal(("b" * 100 + "\x17").b) << sealer.seal("fin\x16".b)
    assert_equal plaintext(:handshake, "fin".b), reader.read(epoch: :handshake, skip_early_data: 200)
    # Skipping has ended: a record that does not open fails now.
    reader << early.seal("c\x17".b)
    assert_equal failure(:bad_record_mac, :bad_record_mac), reader.read(epoch: :handshake, skip_early_data: 200)
  end

  def test_skipping_past_the_limit
    reader, = reader_and_sealer
    early = Record::Protection.new(secret: RFC8448::SERVER_HANDSHAKE_TRAFFIC_SECRET, cipher_suite: SUITE)
    reader << early.seal(("a" * 100 + "\x17").b) << early.seal(("b" * 100 + "\x17").b)
    assert_equal failure(:unexpected_message, :too_much_early_data), reader.read(epoch: :handshake, skip_early_data: 199)
  end

  # Empty 0-RTT records count once each, so a flood of them reaches the
  # limit too; a record too short for a tag and a content type was never
  # 0-RTT.
  def test_skipping_empty_and_short_records
    reader, = reader_and_sealer
    early = Record::Protection.new(secret: RFC8448::SERVER_HANDSHAKE_TRAFFIC_SECRET, cipher_suite: SUITE)
    3.times { reader << early.seal("\x17".b) }
    assert_equal failure(:unexpected_message, :too_much_early_data), reader.read(epoch: :handshake, skip_early_data: 2)
    reader, = reader_and_sealer
    reader << [23, 0x0303, 16].pack("Cnn") + "\x00".b * 16
    assert_equal failure(:bad_record_mac, :bad_record_mac), reader.read(epoch: :handshake, skip_early_data: 1024)
  end

  # After a HelloRetryRequest the server reads in the clear: records of
  # application_data are skipped, the client's change_cipher_spec passes,
  # and its second ClientHello ends the skipping.
  def test_skipping_rejected_0rtt_in_the_clear
    reader = layer
    early = Record::Protection.new(secret: SECRET, cipher_suite: SUITE)
    reader << plaintext_record(20, "\x01") << early.seal(("a" * 10 + "\x17").b) << server_hello_record << early.seal("b\x17".b)
    assert_equal plaintext(:change_cipher_spec, "\x01".b), reader.read(epoch: :initial, skip_early_data: 100)
    assert_equal plaintext(:handshake, RFC8448::SERVER_HELLO), reader.read(epoch: :initial, skip_early_data: 100)
    assert_equal failure(:unexpected_message, :unexpected_record), reader.read(epoch: :initial, skip_early_data: 100)
  end

  def test_our_record_size_limit
    reader, sealer = reader_and_sealer
    reader.limit_sizes(receive: 100)
    reader << sealer.seal("x".b * 99 + "\x17".b)
    assert_equal plaintext(:application_data, "x".b * 99), reader.read(epoch: :handshake)
    reader << sealer.seal("x".b * 100 + "\x17".b)
    assert_equal failure(:record_overflow, :record_too_large), reader.read(epoch: :handshake)
    # Padding counts too.
    reader, sealer = reader_and_sealer
    reader.limit_sizes(receive: 100)
    reader << sealer.seal("x\x17".b + "\x00".b * 99)
    assert_equal failure(:record_overflow, :record_too_large), reader.read(epoch: :handshake)
    reader, sealer = reader_and_sealer
    reader.limit_sizes(receive: 100)
    reader << sealer.seal("x".b * 400 + "\x17".b)
    assert_equal failure(:record_overflow, :record_too_large), reader.read(epoch: :handshake)
  end

  # With a confidentiality limit of 3 records, the third is the KeyUpdate.
  def test_key_update_due
    limits = { tcp: TLS::CipherSuite::Limits.new(confidentiality: 3, integrity: nil), quic: TLS::CipherSuite::Limits.new(confidentiality: 3, integrity: 3) }
    small = SUITE.with(limits:)
    rec = layer
    refute rec.key_update_due?(:application)
    rec.install(direction: :write, epoch: :application, secret: SECRET, cipher_suite: small)
    rec.write(content_type: :application_data, payload: "a", epoch: :application)
    refute rec.key_update_due?(:application)
    rec.write(content_type: :application_data, payload: "b", epoch: :application)
    assert rec.key_update_due?(:application)
    rec.install(direction: :write, epoch: :application, secret: SECRET.reverse, cipher_suite: small)
    refute rec.key_update_due?(:application)
    rec.install(direction: :write, epoch: :application, secret: SECRET, cipher_suite: TLS::CipherSuite::TLS_CHACHA20_POLY1305_SHA256)
    refute rec.key_update_due?(:application)
  end

  def test_misuse
    assert_raises(ArgumentError) { Record::Layer.new(profile: TLS::Profile::QUIC) }
    rec = layer
    assert_raises(TLS::UsageError) { rec.install(direction: :read, epoch: :initial, secret: SECRET, cipher_suite: SUITE) }
    assert_raises(TLS::UsageError) { rec.write(content_type: :handshake, payload: "x", epoch: :handshake) }
    assert_raises(ArgumentError) { rec.write(content_type: :heartbeat, payload: "x", epoch: :initial) }
    rec << RFC8448::CLIENT_FINISHED_RECORD
    assert_raises(TLS::UsageError) { rec.read(epoch: :handshake) }
  end

  def test_discard_forgets_keys_and_bytes
    reader, = reader_and_sealer
    reader << "\x16\x03".b
    protection = reader.instance_variable_get(:@read).fetch(:handshake)
    reader.discard!
    assert_equal 0, reader.pending_bytes
    assert_empty protection.instance_variable_get(:@iv)
    assert_raises(TLS::UsageError) { reader.write(content_type: :handshake, payload: "x", epoch: :handshake) }
  end
end
