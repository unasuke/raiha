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

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_SERVER_HANDSHAKE_WRITE_TRAFFIC_KEY = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_SERVER_HANDSHAKE_WRITE_TRAFFIC_IV = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    5d 31 3e b2 67 12 76 ee 13 00 0b 30
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_ENCRYPTED_EXTENSIONS = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    08 00 00 24 00 22 00 0a 00 14 00
    12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
    00 02 40 01 00 00 00 00
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    0b 00 01 b9 00 00 01 b5 00 01 b0 30 82
    01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
    86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03
    72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17
    0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06
    03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7
    0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f
    82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
    d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c
    1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52
    4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74
    80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93
    ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03
    01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
    03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01
    01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a
    72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea
    e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01
    51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
    c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b
    1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8
    96 12 29 ac 91 87 b4 2b 4d e1 00 00
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE_VERIFY = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    0f 00 00 84 08 04 00 80 5a 74 7c
    5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
    b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
    86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
    be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
    5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
    3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_FINISHED = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb
    dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07
    18
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_DERIVED_CLIENT_APPLICATION_TRAFFIC_SECRET_0 = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_DERIVED_SERVER_APPLICATION_TRAFFIC_SECRET_0 = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_SERVER_APPLICATION_WRITE_TRAFFIC_KEY = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_SERVER_APPLICATION_WRITE_TRAFFIC_IV = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    cf 78 2b 88 dd 83 54 9a ad f1 e9 84
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_CLIENT_APPLICATION_WRITE_TRAFFIC_KEY = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51
  HEX

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_CLIENT_APPLICATION_WRITE_TRAFFIC_IV = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    5b 78 92 3d ee 08 57 90 33 e5 23 d9
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
      key_schedule.derive_client_handshake_traffic_secret([
          ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
          ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
        ])
    end
    key_schedule.compute_shared_secret
    key_schedule.derive_secret(secret: :early_secret, label: "derived", messages: [""])
    key_schedule.derive_client_handshake_traffic_secret([
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    ])
    assert_equal_bin RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_CLIENT_HANDSHAKE_TRAFFIC, key_schedule.client_handshake_traffic_secret
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
      key_schedule.derive_server_handshake_traffic_secret([
          ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
          ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
        ])
    end
    key_schedule.compute_shared_secret
    key_schedule.derive_secret(secret: :early_secret, label: "derived", messages: [""])
    key_schedule.derive_server_handshake_traffic_secret([
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    ])
    assert_equal_bin RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_SERVER_HANDSHAKE_TRAFFIC, key_schedule.server_handshake_traffic_secret
    assert_equal_bin RFC8448_1RTT_SERVER_HANDSHAKE_WRITE_TRAFFIC_KEY, key_schedule.server_handshake_write_key
    assert_equal_bin RFC8448_1RTT_SERVER_HANDSHAKE_WRITE_TRAFFIC_IV, key_schedule.server_handshake_write_iv
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
    key_schedule.derive_client_handshake_traffic_secret([
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    ])
    assert_equal_bin RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_CLIENT_HANDSHAKE_TRAFFIC, key_schedule.client_handshake_traffic_secret
  end

  def test_derive_application_traffic_secret_rfc8448_1rtt
    key_schedule = ::Raiha::TLS::KeySchedule.new(mode: :server).tap do |ks|
      ks.cipher_suite = ::Raiha::TLS::CipherSuite.new(:TLS_AES_128_GCM_SHA256)
      ks.pkey = OpenSSL::PKey.new_raw_private_key("x25519", RFC8448_1RTT_CLIENT_EPHEMERAL_X25519_PRIVATE_KEY)
      ks.group = "x25519"
      ks.public_key = RFC8448_1RTT_SERVER_EPHEMERAL_X25519_PUBLIC_KEY
    end
    key_schedule.compute_shared_secret
    key_schedule.derive_secret(secret: :early_secret, label: "derived", messages: [""])
    key_schedule.derive_client_handshake_traffic_secret([
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    ])
    key_schedule.derive_server_handshake_traffic_secret([
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    ])
    assert_equal_bin RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_CLIENT_HANDSHAKE_TRAFFIC, key_schedule.client_handshake_traffic_secret
    assert_equal_bin RFC8448_1RTT_DERIVED_SECRET_FOR_HANDSHAKE_TLS13_SERVER_HANDSHAKE_TRAFFIC, key_schedule.server_handshake_traffic_secret

    messages = [
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_ENCRYPTED_EXTENSIONS),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE_VERIFY),
      ::Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_FINISHED),
    ]
    key_schedule.derive_client_application_traffic_secret(messages)
    key_schedule.derive_server_application_traffic_secret(messages)
    assert_equal_bin RFC8448_1RTT_DERIVED_CLIENT_APPLICATION_TRAFFIC_SECRET_0, key_schedule.client_application_traffic_secret[0]
    assert_equal_bin RFC8448_1RTT_DERIVED_SERVER_APPLICATION_TRAFFIC_SECRET_0, key_schedule.server_application_traffic_secret[0]
    assert_equal_bin RFC8448_1RTT_SERVER_APPLICATION_WRITE_TRAFFIC_KEY, key_schedule.server_application_write_key
    assert_equal_bin RFC8448_1RTT_SERVER_APPLICATION_WRITE_TRAFFIC_IV, key_schedule.server_application_write_iv
    assert_equal_bin RFC8448_1RTT_CLIENT_APPLICATION_WRITE_TRAFFIC_KEY, key_schedule.client_application_write_key
    assert_equal_bin RFC8448_1RTT_CLIENT_APPLICATION_WRITE_TRAFFIC_IV, key_schedule.client_application_write_iv
  end
end
