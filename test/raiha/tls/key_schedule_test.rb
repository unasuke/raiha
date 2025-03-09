require "test_helper"
require "support/rfc8448_test_vector"
require "raiha/tls/key_schedule"
require "raiha/tls/transcript_hash"
require "raiha/tls/handshake"
require "openssl"

class RaihaTLSKeyScheduleTest < Minitest::Test
  def test_compute_shared_secret_prime256v1
    client_pkey = OpenSSL::PKey::EC.generate("prime256v1")
    server_pkey = OpenSSL::PKey::EC.generate("prime256v1")

    client_key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :client).tap do |ks|
      ks.pkey = client_pkey
      ks.group = "prime256v1"
      ks.public_key = server_pkey.public_key.to_octet_string(:uncompressed)
    end

    server_key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.pkey = server_pkey
      ks.group = "prime256v1"
      ks.public_key = client_pkey.public_key.to_octet_string(:uncompressed)
    end

    client_key_schedule.compute_shared_secret
    server_key_schedule.compute_shared_secret

    assert_equal client_key_schedule.shared_secret, server_key_schedule.shared_secret
  end

  def test_compute_shared_secret_secp384r1
    client_pkey = OpenSSL::PKey::EC.generate("secp384r1")
    server_pkey = OpenSSL::PKey::EC.generate("secp384r1")

    client_key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :client).tap do |ks|
      ks.pkey = client_pkey
      ks.group = "secp384r1"
      ks.public_key = server_pkey.public_key.to_octet_string(:uncompressed)
    end

    server_key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.pkey = server_pkey
      ks.group = "secp384r1"
      ks.public_key = client_pkey.public_key.to_octet_string(:uncompressed)
    end

    client_key_schedule.compute_shared_secret
    server_key_schedule.compute_shared_secret

    assert_equal client_key_schedule.shared_secret, server_key_schedule.shared_secret
  end

  def test_compute_shared_secret_rfc8448_x25519
    client_key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :client).tap do |ks|
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_SIMPLE_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_SIMPLE_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY
    end

    server_key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_SIMPLE_1RTT_SERVER_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_SIMPLE_1RTT_CLIENT_EPHEMERAL_X25519_PUBLIC_KEY
    end

    client_key_schedule.compute_shared_secret
    server_key_schedule.compute_shared_secret

    assert_equal_bin client_key_schedule.shared_secret, server_key_schedule.shared_secret
    assert_equal_bin client_key_schedule.shared_secret, RFC8448_SIMPLE_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_IKM
    assert_equal_bin server_key_schedule.shared_secret, RFC8448_SIMPLE_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_IKM # double check ;)
  end

  def test_derive_secret_rfc8448_1rtt_handshake_derived
    transcript_hash = ::Raiha::TLS::TranscriptHash.new.tap do |th|
      th.digest_algorithm = "sha256"
    end
    key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
    end
    derived = key_schedule.derive_secret(secret: :early_secret, label: "derived", transcript_hash: transcript_hash.hash)
    assert_equal_bin RFC8448_SIMPLE_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_DERIVED, derived
  end

  def test_derive_secret_rfc8448_1rtt_handshake_tls13_client_handshake_traffic_secret
    transcript_hash = ::Raiha::TLS::TranscriptHash.new.tap do |th|
      th.digest_algorithm = "sha256"
    end
    key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_SIMPLE_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_SIMPLE_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY
    end

    assert_raises do
      # didn't derive early secret yet
      key_schedule.derive_client_handshake_traffic_secret(transcript_hash.hash)
    end
    key_schedule.compute_shared_secret
    key_schedule.derive_secret(secret: :early_secret, label: "derived", transcript_hash: transcript_hash.hash)

    transcript_hash[:client_hello] = RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO
    transcript_hash[:server_hello] = RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO
    key_schedule.derive_client_handshake_traffic_secret(transcript_hash.hash)
    assert_equal_bin RFC8448_SIMPLE_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_CLIENT_HANDSHAKE_TRAFFIC, key_schedule.client_handshake_traffic_secret
  end

  def test_derive_secret_rfc8448_1rtt_handshake_tls13_server_handshake_traffic_secret
    transcript_hash = ::Raiha::TLS::TranscriptHash.new.tap do |th|
      th.digest_algorithm = "sha256"
    end
    key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_SIMPLE_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_SIMPLE_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY
    end

    assert_raises do
      # didn't derive early secret yet
      key_schedule.derive_server_handshake_traffic_secret(transcript_hash.hash)
    end
    key_schedule.compute_shared_secret
    key_schedule.derive_secret(secret: :early_secret, label: "derived", transcript_hash: transcript_hash.hash)

    transcript_hash[:client_hello] = RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO
    transcript_hash[:server_hello] = RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO
    key_schedule.derive_server_handshake_traffic_secret(transcript_hash.hash)
    assert_equal_bin RFC8448_SIMPLE_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_SERVER_HANDSHAKE_TRAFFIC, key_schedule.server_handshake_traffic_secret
    assert_equal_bin RFC8448_SIMPLE_1RTT_SERVER_HANDSHAKE_WRITE_TRAFFIC_KEY, key_schedule.server_handshake_write_key
    assert_equal_bin RFC8448_SIMPLE_1RTT_SERVER_HANDSHAKE_WRITE_TRAFFIC_IV, key_schedule.server_handshake_write_iv
  end

  def test_derive_secret_rfc8448_1rtt_handshake_tls13_client_application_traffic_secret_0
    transcript_hash = ::Raiha::TLS::TranscriptHash.new.tap do |th|
      th.digest_algorithm = "sha256"
    end
    key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_SIMPLE_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_SIMPLE_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY
    end

    key_schedule.compute_shared_secret
    key_schedule.derive_secret(secret: :early_secret, label: "derived", transcript_hash: transcript_hash.hash)
    transcript_hash[:client_hello] = RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO
    transcript_hash[:server_hello] = RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO
    key_schedule.derive_client_handshake_traffic_secret(transcript_hash.hash)
    assert_equal_bin RFC8448_SIMPLE_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_CLIENT_HANDSHAKE_TRAFFIC, key_schedule.client_handshake_traffic_secret
  end

  def test_derive_application_traffic_secret_rfc8448_1rtt
    transcript_hash = ::Raiha::TLS::TranscriptHash.new.tap do |th|
      th.digest_algorithm = "sha256"
    end
    key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_SIMPLE_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_SIMPLE_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY
    end
    key_schedule.compute_shared_secret
    key_schedule.derive_secret(secret: :early_secret, label: "derived", transcript_hash: transcript_hash.hash)

    transcript_hash[:client_hello] = RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO
    transcript_hash[:server_hello] = RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO
    key_schedule.derive_client_handshake_traffic_secret(transcript_hash.hash)
    key_schedule.derive_server_handshake_traffic_secret(transcript_hash.hash)
    assert_equal_bin RFC8448_SIMPLE_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_CLIENT_HANDSHAKE_TRAFFIC, key_schedule.client_handshake_traffic_secret
    assert_equal_bin RFC8448_SIMPLE_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_SERVER_HANDSHAKE_TRAFFIC, key_schedule.server_handshake_traffic_secret

    transcript_hash[:encrypted_extensions] = RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_ENCRYPTED_EXTENSIONS
    transcript_hash[:certificate] = RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE
    transcript_hash[:certificate_verify] = RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE_VERIFY
    transcript_hash[:finished] = RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_FINISHED

    key_schedule.derive_client_application_traffic_secret(transcript_hash.hash)
    key_schedule.derive_server_application_traffic_secret(transcript_hash.hash)
    assert_equal_bin RFC8448_SIMPLE_1RTT_DERIVED_CLIENT_APPLICATION_TRAFFIC_SECRET_0, key_schedule.client_application_traffic_secret[0]
    assert_equal_bin RFC8448_SIMPLE_1RTT_DERIVED_SERVER_APPLICATION_TRAFFIC_SECRET_0, key_schedule.server_application_traffic_secret[0]
    assert_equal_bin RFC8448_SIMPLE_1RTT_SERVER_APPLICATION_WRITE_TRAFFIC_KEY, key_schedule.server_application_write_key
    assert_equal_bin RFC8448_SIMPLE_1RTT_SERVER_APPLICATION_WRITE_TRAFFIC_IV, key_schedule.server_application_write_iv
    assert_equal_bin RFC8448_SIMPLE_1RTT_CLIENT_APPLICATION_WRITE_TRAFFIC_KEY, key_schedule.client_application_write_key
    assert_equal_bin RFC8448_SIMPLE_1RTT_CLIENT_APPLICATION_WRITE_TRAFFIC_IV, key_schedule.client_application_write_iv
  end
end
