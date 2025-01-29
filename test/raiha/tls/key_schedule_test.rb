require "test_helper"
require "raiha/tls/key_schedule"
require "openssl"

class RaihaTLSKeyScheduleTest < Minitest::Test
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
end
