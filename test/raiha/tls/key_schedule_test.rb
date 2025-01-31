require "test_helper"
require "raiha/tls/key_schedule"
require "raiha/tls/handshake"
require "openssl"

class RaihaTLSKeyScheduleTest < Minitest::Test
  # https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO = [<<~HS.gsub(/[[:space:]]/, '')].pack("H*")
    01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
    ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
    02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
    00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
    12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
    00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
    3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
    af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
    02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
    02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01
  HS

  # https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO = [<<~SH.gsub(/[[:space:]]/, '')].pack("H*")
    02 00 00 56 03 03 a6 af 06 a4 12 18 60
    dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
    d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88
    76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1
    dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04
  SH

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_CLIENT_EPHEMERAL_X25519_PUBLIC_KEY = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_SERVER_EPHEMERAL_X25519_PRIVATE_KEY = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56 52 57 8c c8 10 e9 98 01 91 ec 8d 05 83 08 ce a2 16 a2 1e
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_IKM = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_DERIVED = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_CLIENT_HANDSHAKE_TRAFFIC = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_SERVER_HANDSHAKE_TRAFFIC = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38
  HEX

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
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY
    end

    server_key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_1RTT_SERVER_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_1RTT_CLIENT_EPHEMERAL_X25519_PUBLIC_KEY
    end

    client_key_schedule.compute_shared_secret
    server_key_schedule.compute_shared_secret

    assert_equal client_key_schedule.shared_secret, server_key_schedule.shared_secret
    assert_equal client_key_schedule.shared_secret, RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_IKM
    assert_equal server_key_schedule.shared_secret, RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_IKM # double check ;)
  end

  def test_derive_secret_rfc8448_1rtt_handshake_derived
    key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
    end
    derived = key_schedule.derive_secret(secret: :early_secret, label: "derived", messages: [""])
    assert_equal RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_DERIVED, derived
  end

  def test_derive_secret_rfc8448_1rtt_handshake_tls13_client_handshake_traffic_secret
    key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY
    end

    assert_raises do
      # didn't derive early secret yet
      key_schedule.client_handshake_traffic_secret([
          ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
          ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
        ])
    end
    key_schedule.compute_shared_secret
    key_schedule.derive_secret(secret: :early_secret, label: "derived", messages: [""])
    derived = key_schedule.client_handshake_traffic_secret([
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    ])
    assert_equal RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_CLIENT_HANDSHAKE_TRAFFIC, derived
  end

  def test_derive_secret_rfc8448_1rtt_handshake_tls13_server_handshake_traffic_secret
    key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY
    end

    assert_raises do
      # didn't derive early secret yet
      key_schedule.server_handshake_traffic_secret([
          ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
          ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
        ])
    end
    key_schedule.compute_shared_secret
    key_schedule.derive_secret(secret: :early_secret, label: "derived", messages: [""])
    derived = key_schedule.server_handshake_traffic_secret([
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    ])
    assert_equal RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_SERVER_HANDSHAKE_TRAFFIC, derived
  end

  def test_derive_secret_rfc8448_1rtt_handshake_tls13_client_application_traffic_secret_0
    key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY
    end

    key_schedule.compute_shared_secret
    key_schedule.derive_secret(secret: :early_secret, label: "derived", messages: [""])
    derived = key_schedule.client_handshake_traffic_secret([
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    ])
    assert_equal RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_CLIENT_HANDSHAKE_TRAFFIC, derived
  end
end
