require "raiha/next/test_helper"
require "raiha/next/tls/test"

# RFC 8448 reproduced end to end from injected keys: the shared secret from
# FixedKEM, the transcript from the wire bytes, and every secret, key and
# Finished value derived from them, byte for byte.
class RaihaNextTLSRFC8448KeyScheduleTest < Minitest::Test
  TLS = Raiha::Next::TLS
  KeySchedule = TLS::KeySchedule
  LABELS = KeySchedule::LABELS
  RFC8448 = TLS::Test::RFC8448

  def derive(secret, label, transcript_hash, hash)
    KeySchedule.derive_secret(secret:, label: LABELS.fetch(label), transcript_hash:, hash:)
  end

  def expand(secret, label, length, hash)
    KeySchedule.expand_label(secret:, label: LABELS.fetch(label), length:, hash:)
  end

  def verify_data(traffic_secret, transcript_hash, suite)
    finished_key = expand(traffic_secret, :finished, suite.hash_length, suite.hash_algorithm)
    TLS::Crypto.hmac(hash: suite.hash_algorithm, key: finished_key, data: transcript_hash)
  end

  def test_simple_1rtt
    s = RFC8448::Simple1RTT
    client_kem = TLS::Test::FixedKEM.new(x25519: s::CLIENT_X25519_PRIVATE_KEY)
    server_kem = TLS::Test::FixedKEM.new(x25519: s::SERVER_X25519_PRIVATE_KEY)
    client_key = client_kem.generate(:x25519)
    server_share, shared_secret = server_kem.encapsulate(:x25519, client_key.public_bytes)
    assert_equal_bin shared_secret, client_kem.decapsulate(client_key, server_share)

    registry = TLS::Extension::Registry::BUILTIN
    suite = TLS::CipherSuite.find(TLS::Handshake.parse(s::SERVER_HELLO, registry:).cipher_suite)
    hash = suite.hash_algorithm
    zeros = "\x00".b * suite.hash_length
    empty_hash = TLS::Crypto.hash(hash, "")

    transcript = TLS::Transcript.new(hashes: [:sha256, :sha384])
    transcript << s::CLIENT_HELLO << s::SERVER_HELLO
    transcript.select!(hash)

    early = KeySchedule.extract(salt: zeros, ikm: zeros, hash:)
    handshake = KeySchedule.extract(salt: derive(early, :derived, empty_hash, hash), ikm: shared_secret, hash:)
    assert_equal_bin s::HANDSHAKE_SECRET, handshake
    client_hs = derive(handshake, :client_handshake_traffic, transcript.digest, hash)
    server_hs = derive(handshake, :server_handshake_traffic, transcript.digest, hash)
    assert_equal_bin s::CLIENT_HANDSHAKE_TRAFFIC_SECRET, client_hs
    assert_equal_bin s::SERVER_HANDSHAKE_TRAFFIC_SECRET, server_hs
    assert_equal_bin s::SERVER_HANDSHAKE_WRITE_KEY, expand(server_hs, :key, suite.key_length, hash)
    assert_equal_bin s::SERVER_HANDSHAKE_WRITE_IV, expand(server_hs, :iv, suite.iv_length, hash)

    transcript << s::ENCRYPTED_EXTENSIONS << s::CERTIFICATE << s::CERTIFICATE_VERIFY
    assert_equal_bin s::SERVER_FINISHED.byteslice(4..), verify_data(server_hs, transcript.digest, suite)
    transcript << s::SERVER_FINISHED

    main = KeySchedule.extract(salt: derive(handshake, :derived, empty_hash, hash), ikm: zeros, hash:)
    assert_equal_bin s::MAIN_SECRET, main
    client_ap = derive(main, :client_application_traffic, transcript.digest, hash)
    assert_equal_bin s::CLIENT_APPLICATION_TRAFFIC_SECRET_0, client_ap
    assert_equal_bin s::SERVER_APPLICATION_TRAFFIC_SECRET_0, derive(main, :server_application_traffic, transcript.digest, hash)
    assert_equal_bin s::EXPORTER_SECRET, derive(main, :exporter, transcript.digest, hash)
    assert_equal_bin s::CLIENT_APPLICATION_WRITE_KEY, expand(client_ap, :key, suite.key_length, hash)

    assert_equal_bin s::CLIENT_FINISHED.byteslice(4..), verify_data(client_hs, transcript.digest, suite)
    transcript << s::CLIENT_FINISHED
    assert_equal_bin s::RESUMPTION_SECRET, derive(main, :resumption, transcript.digest, hash)
  end

  def test_hello_retry_request
    h = RFC8448::HelloRetryRequest
    client_kem = TLS::Test::FixedKEM.new(secp256r1: h::CLIENT_SECP256R1_PRIVATE_KEY)
    server_kem = TLS::Test::FixedKEM.new(secp256r1: h::SERVER_SECP256R1_PRIVATE_KEY)
    client_key = client_kem.generate(:secp256r1)
    _server_share, shared_secret = server_kem.encapsulate(:secp256r1, client_key.public_bytes)
    assert_equal_bin h::HANDSHAKE_IKM, shared_secret

    transcript = TLS::Transcript.new(hashes: [:sha256, :sha384])
    transcript << h::CLIENT_HELLO_1
    transcript.select!(:sha256)
    transcript.restart_with_message_hash!
    transcript << h::HELLO_RETRY_REQUEST << h::CLIENT_HELLO_2 << h::SERVER_HELLO
    assert_equal_bin h::HELLO_TRANSCRIPT_HASH, transcript.digest
    transcript << h::ENCRYPTED_EXTENSIONS << h::CERTIFICATE << h::CERTIFICATE_VERIFY

    zeros = "\x00".b * 32
    early = KeySchedule.extract(salt: zeros, ikm: zeros, hash: :sha256)
    handshake = KeySchedule.extract(salt: derive(early, :derived, TLS::Crypto.hash(:sha256, ""), :sha256), ikm: shared_secret, hash: :sha256)
    server_hs = derive(handshake, :server_handshake_traffic, h::HELLO_TRANSCRIPT_HASH, :sha256)
    assert_equal_bin h::SERVER_FINISHED.byteslice(4..), verify_data(server_hs, transcript.digest, TLS::CipherSuite::TLS_AES_128_GCM_SHA256)
  end
end
