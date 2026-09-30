require "raiha/next/test_helper"
require "raiha/next/tls/test"

# The RFC 8448 section 3 key schedule, secret by secret. Each value must match
# byte for byte before anything else is built on top of it.
class RaihaNextTLSKeyScheduleTest < Minitest::Test
  TLS = Raiha::Next::TLS
  KeySchedule = TLS::KeySchedule
  LABELS = KeySchedule::LABELS
  RFC8448 = TLS::Test::RFC8448::Simple1RTT
  ZEROS = "\x00".b * 32

  def derive(secret, label, transcript_hash)
    KeySchedule.derive_secret(secret:, label: LABELS.fetch(label), transcript_hash:, hash: :sha256)
  end

  def expand(secret, label, length, context: "".b)
    KeySchedule.expand_label(secret:, label: LABELS.fetch(label), context:, length:, hash: :sha256)
  end

  def test_early_secret
    assert_equal_bin RFC8448::EARLY_SECRET, KeySchedule.extract(salt: ZEROS, ikm: ZEROS, hash: :sha256)
  end

  def test_handshake_secret
    salt = derive(RFC8448::EARLY_SECRET, :derived, RFC8448::EMPTY_HASH)
    assert_equal_bin RFC8448::DERIVED_SECRET_FOR_HANDSHAKE, salt
    assert_equal_bin RFC8448::HANDSHAKE_SECRET, KeySchedule.extract(salt:, ikm: RFC8448::HANDSHAKE_IKM, hash: :sha256)
  end

  def test_handshake_traffic_secrets
    assert_equal_bin RFC8448::CLIENT_HANDSHAKE_TRAFFIC_SECRET,
      derive(RFC8448::HANDSHAKE_SECRET, :client_handshake_traffic, RFC8448::HELLO_TRANSCRIPT_HASH)
    assert_equal_bin RFC8448::SERVER_HANDSHAKE_TRAFFIC_SECRET,
      derive(RFC8448::HANDSHAKE_SECRET, :server_handshake_traffic, RFC8448::HELLO_TRANSCRIPT_HASH)
  end

  def test_main_secret
    salt = derive(RFC8448::HANDSHAKE_SECRET, :derived, RFC8448::EMPTY_HASH)
    assert_equal_bin RFC8448::DERIVED_SECRET_FOR_MAIN, salt
    assert_equal_bin RFC8448::MAIN_SECRET, KeySchedule.extract(salt:, ikm: ZEROS, hash: :sha256)
  end

  def test_application_traffic_and_exporter_secrets
    assert_equal_bin RFC8448::CLIENT_APPLICATION_TRAFFIC_SECRET_0,
      derive(RFC8448::MAIN_SECRET, :client_application_traffic, RFC8448::SERVER_FINISHED_TRANSCRIPT_HASH)
    assert_equal_bin RFC8448::SERVER_APPLICATION_TRAFFIC_SECRET_0,
      derive(RFC8448::MAIN_SECRET, :server_application_traffic, RFC8448::SERVER_FINISHED_TRANSCRIPT_HASH)
    assert_equal_bin RFC8448::EXPORTER_SECRET,
      derive(RFC8448::MAIN_SECRET, :exporter, RFC8448::SERVER_FINISHED_TRANSCRIPT_HASH)
  end

  def test_resumption_secret_and_ticket_psk
    resumption = derive(RFC8448::MAIN_SECRET, :resumption, RFC8448::CLIENT_FINISHED_TRANSCRIPT_HASH)
    assert_equal_bin RFC8448::RESUMPTION_SECRET, resumption
    assert_equal_bin RFC8448::TICKET_PSK, expand(resumption, :ticket_psk, 32, context: "\x00\x00".b)
  end

  def test_traffic_keys
    assert_equal_bin RFC8448::SERVER_HANDSHAKE_WRITE_KEY, expand(RFC8448::SERVER_HANDSHAKE_TRAFFIC_SECRET, :key, 16)
    assert_equal_bin RFC8448::SERVER_HANDSHAKE_WRITE_IV, expand(RFC8448::SERVER_HANDSHAKE_TRAFFIC_SECRET, :iv, 12)
    assert_equal_bin RFC8448::CLIENT_HANDSHAKE_WRITE_KEY, expand(RFC8448::CLIENT_HANDSHAKE_TRAFFIC_SECRET, :key, 16)
    assert_equal_bin RFC8448::CLIENT_HANDSHAKE_WRITE_IV, expand(RFC8448::CLIENT_HANDSHAKE_TRAFFIC_SECRET, :iv, 12)
    assert_equal_bin RFC8448::SERVER_APPLICATION_WRITE_KEY, expand(RFC8448::SERVER_APPLICATION_TRAFFIC_SECRET_0, :key, 16)
    assert_equal_bin RFC8448::CLIENT_APPLICATION_WRITE_IV, expand(RFC8448::CLIENT_APPLICATION_TRAFFIC_SECRET_0, :iv, 12)
  end

  # verify_data is the HMAC, under the finished key, of the transcript hash up
  # to the message before Finished.
  def test_finished_keys_and_verify_data
    server_key = expand(RFC8448::SERVER_HANDSHAKE_TRAFFIC_SECRET, :finished, 32)
    assert_equal_bin RFC8448::SERVER_FINISHED_KEY, server_key
    through_cv = TLS::Crypto.hash(:sha256, RFC8448::CLIENT_HELLO + RFC8448::SERVER_HELLO +
      RFC8448::ENCRYPTED_EXTENSIONS + RFC8448::CERTIFICATE + RFC8448::CERTIFICATE_VERIFY)
    assert_equal_bin RFC8448::SERVER_FINISHED.byteslice(4..),
      TLS::Crypto.hmac(hash: :sha256, key: server_key, data: through_cv)

    client_key = expand(RFC8448::CLIENT_HANDSHAKE_TRAFFIC_SECRET, :finished, 32)
    assert_equal_bin RFC8448::CLIENT_FINISHED_KEY, client_key
    assert_equal_bin RFC8448::CLIENT_FINISHED.byteslice(4..),
      TLS::Crypto.hmac(hash: :sha256, key: client_key, data: RFC8448::SERVER_FINISHED_TRANSCRIPT_HASH)
  end

  def test_expand_label_encodes_hkdf_label
    # From RFC 8448: the info for "tls13 c hs traffic" with a 32-byte hash.
    info = "\x00\x20\x12tls13 c hs traffic\x20".b + RFC8448::HELLO_TRANSCRIPT_HASH
    expected = TLS::Crypto::HKDF.expand(hash: :sha256, prk: RFC8448::HANDSHAKE_SECRET, info:, length: 32)
    assert_equal_bin expected, derive(RFC8448::HANDSHAKE_SECRET, :client_handshake_traffic, RFC8448::HELLO_TRANSCRIPT_HASH)
  end

  def test_labels_outside_the_table_work_too
    # QUIC derives its packet protection keys with labels of its own.
    key = KeySchedule.expand_label(secret: RFC8448::CLIENT_HANDSHAKE_TRAFFIC_SECRET, label: "quic key", length: 16, hash: :sha256)
    assert_equal 16, key.bytesize
  end

  def test_label_length_is_bounded
    assert_raises(TLS::Codec::EncodeError) do
      KeySchedule.expand_label(secret: ZEROS, label: "x" * 250, length: 32, hash: :sha256)
    end
  end
end
