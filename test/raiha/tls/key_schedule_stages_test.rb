require "test_helper"
require "raiha/tls/test"

# A KeySchedule instance walking RFC 8448 through its stages, and the order
# it enforces.
class RaihaNextTLSKeyScheduleStagesTest < Minitest::Test
  TLS = Raiha::TLS
  KeySchedule = TLS::KeySchedule
  S = TLS::Test::RFC8448::Simple1RTT
  R = TLS::Test::RFC8448::Resumed0RTT

  def sha256(data) = TLS::Crypto.hash(:sha256, data)

  def handshake_stage
    ks = KeySchedule.new(hash: :sha256)
    ks.handshake!(S::HANDSHAKE_IKM)
  end

  # The transcript hash through the server CertificateVerify, which the
  # server Finished covers. The vectors' SERVER_FINISHED_TRANSCRIPT_HASH runs
  # through the server Finished and CLIENT_FINISHED_TRANSCRIPT_HASH through
  # the client Finished.
  def through_certificate_verify
    sha256(S::CLIENT_HELLO + S::SERVER_HELLO + S::ENCRYPTED_EXTENSIONS + S::CERTIFICATE + S::CERTIFICATE_VERIFY)
  end

  def test_rfc8448_simple_1rtt
    ks = handshake_stage
    assert_equal :handshake, ks.stage
    assert_equal_bin S::CLIENT_HANDSHAKE_TRAFFIC_SECRET, ks.client_handshake_traffic_secret(S::HELLO_TRANSCRIPT_HASH)
    assert_equal_bin S::SERVER_HANDSHAKE_TRAFFIC_SECRET, ks.server_handshake_traffic_secret(S::HELLO_TRANSCRIPT_HASH)
    assert ks.verify_finished(:server, through_certificate_verify, S::SERVER_FINISHED.byteslice(4..))

    ks.main!
    assert_equal_bin S::CLIENT_APPLICATION_TRAFFIC_SECRET_0, ks.client_application_traffic_secret(S::SERVER_FINISHED_TRANSCRIPT_HASH)
    assert_equal_bin S::SERVER_APPLICATION_TRAFFIC_SECRET_0, ks.server_application_traffic_secret(S::SERVER_FINISHED_TRANSCRIPT_HASH)
    exported = ks.exporter_values(["EXPORTER-test"], S::SERVER_FINISHED_TRANSCRIPT_HASH)
    inner = KeySchedule.derive_secret(secret: S::EXPORTER_SECRET, label: "EXPORTER-test", transcript_hash: sha256(""), hash: :sha256)
    assert_equal({ "EXPORTER-test" => inner }, exported)
    assert_equal_bin S::CLIENT_FINISHED.byteslice(4..), ks.finished_verify_data(:client, S::SERVER_FINISHED_TRANSCRIPT_HASH)

    ks.resumption!(S::CLIENT_FINISHED_TRANSCRIPT_HASH)
    ticket = TLS::Handshake.parse(S::NEW_SESSION_TICKET, registry: TLS::Extension::Registry::BUILTIN)
    assert_equal_bin S::TICKET_PSK, ks.ticket_psk(ticket.ticket_nonce)
  end

  # RFC 8448 section 4: the binder of the resumed ClientHello is computed
  # over the ClientHello up to the binders, with the PSK of section 3.
  def test_rfc8448_resumption_binder
    ks = KeySchedule.new(hash: :sha256, psk: S::TICKET_PSK)
    binder = R::CLIENT_HELLO.byteslice(-32..)
    assert_equal_bin binder, ks.binder(kind: :resumption, transcript_hash: sha256(R::CLIENT_HELLO_PREFIX))
    assert ks.verify_binder(kind: :resumption, transcript_hash: sha256(R::CLIENT_HELLO_PREFIX), binder:)
    refute ks.verify_binder(kind: :external, transcript_hash: sha256(R::CLIENT_HELLO_PREFIX), binder:)
    refute ks.verify_binder(kind: :resumption, transcript_hash: sha256(R::CLIENT_HELLO_PREFIX), binder: binder.byteslice(0, 31))
    tampered = binder.dup.tap { |b| b.setbyte(0, b.getbyte(0) ^ 1) }
    refute ks.verify_binder(kind: :resumption, transcript_hash: sha256(R::CLIENT_HELLO_PREFIX), binder: tampered)
  end

  def test_peer_finished_of_the_wrong_length_does_not_match
    ks = handshake_stage
    ks.server_handshake_traffic_secret(S::HELLO_TRANSCRIPT_HASH)
    refute ks.verify_finished(:server, through_certificate_verify, S::SERVER_FINISHED.byteslice(4, 31))
  end

  def test_stages_go_in_order
    ks = KeySchedule.new(hash: :sha256)
    assert_raises(TLS::UsageError) { ks.client_handshake_traffic_secret(S::HELLO_TRANSCRIPT_HASH) }
    assert_raises(TLS::UsageError) { ks.main! }
    ks.handshake!(S::HANDSHAKE_IKM)
    assert_raises(TLS::UsageError) { ks.handshake!(S::HANDSHAKE_IKM) }
    assert_raises(TLS::UsageError) { ks.binder(kind: :resumption, transcript_hash: sha256("")) }
    assert_raises(TLS::UsageError) { ks.client_application_traffic_secret(S::CLIENT_FINISHED_TRANSCRIPT_HASH) }
    ks.main!
    assert_raises(TLS::UsageError) { ks.server_handshake_traffic_secret(S::HELLO_TRANSCRIPT_HASH) }
    assert_raises(TLS::UsageError) { ks.ticket_psk("\x00\x00".b) }
    ks.resumption!(sha256(""))
    assert_raises(TLS::UsageError) { ks.exporter_values(["EXPORTER-test"], sha256("")) }
  end

  def test_finished_keys_are_used_once
    ks = handshake_stage
    assert_raises(TLS::UsageError) { ks.finished_verify_data(:client, S::CLIENT_FINISHED_TRANSCRIPT_HASH) }
    ks.client_handshake_traffic_secret(S::HELLO_TRANSCRIPT_HASH)
    ks.finished_verify_data(:client, S::CLIENT_FINISHED_TRANSCRIPT_HASH)
    assert_raises(TLS::UsageError) { ks.finished_verify_data(:client, S::CLIENT_FINISHED_TRANSCRIPT_HASH) }
  end

  def test_update_application_traffic_secret
    ks = handshake_stage.main!
    assert_raises(TLS::UsageError) { ks.update_application_traffic_secret!(:client) }
    current = ks.client_application_traffic_secret(S::CLIENT_FINISHED_TRANSCRIPT_HASH)
    expected = KeySchedule.expand_label(secret: current, label: "traffic upd", length: 32, hash: :sha256)
    assert_equal_bin expected, ks.update_application_traffic_secret!(:client)
    second = KeySchedule.expand_label(secret: expected, label: "traffic upd", length: 32, hash: :sha256)
    assert_equal_bin second, ks.update_application_traffic_secret!(:client)
  end

  def test_no_labels_no_exporter_secret
    assert_equal({}, handshake_stage.main!.exporter_values([], S::CLIENT_FINISHED_TRANSCRIPT_HASH))
  end

  def test_export
    inner = "\x01".b * 32
    expected = KeySchedule.expand_label(secret: inner, label: "exporter", context: sha256("ctx"), length: 16, hash: :sha256)
    assert_equal_bin expected, KeySchedule.export(inner_value: inner, context: "ctx", length: 16, hash: :sha256)
  end

  def test_discard_forgets_every_secret
    ks = handshake_stage
    ks.client_handshake_traffic_secret(S::HELLO_TRANSCRIPT_HASH)
    ks.main!
    handed_out = ks.server_application_traffic_secret(S::CLIENT_FINISHED_TRANSCRIPT_HASH)
    kept = [ks.instance_variable_get(:@secret), *ks.instance_variable_get(:@finished_keys).values,
      *ks.instance_variable_get(:@application_traffic_secrets).values]
    ks.discard!
    assert_equal :discarded, ks.stage
    assert kept.all?(&:empty?)
    assert_equal 32, handed_out.bytesize
    assert_raises(TLS::UsageError) { ks.exporter_values([], sha256("")) }
    assert_raises(TLS::UsageError) { ks.finished_verify_data(:client, sha256("")) }
  end

  def test_inspect_shows_no_secret
    ks = handshake_stage
    assert_match(/\A#<Raiha::TLS::KeySchedule:0x\h+ @hash_algorithm=:sha256, @stage=:handshake>\z/, ks.inspect)
  end
end
