# frozen_string_literal: true

require "test_helper"

require "raiha/quic/crypto/aead"

class RaihaQuicCryptoAEADTest < Minitest::Test
  def test_encrypt_and_decrypt_successful
    plaintext = "Hello, world!"
    key = "0123456789abcdef"
    nonce = "0123456789ab"
    associated_data = "assocdata"
    aead = Raiha::Quic::Crypto::AEAD.new("aes-128-gcm", key, nonce)
    encrypted_data = aead.encrypt(plaintext, associated_data, 1)
    decrypted_data = aead.decrypt(encrypted_data, associated_data, 1)
    assert_equal plaintext, decrypted_data
  end

  def test_encrypt_and_decrypt_fail
    plaintext = "Hello, world!"
    key = "0123456789abcdef"
    nonce = "0123456789ab"
    associated_data = "assocdata"
    aead = Raiha::Quic::Crypto::AEAD.new("aes-128-gcm", key, nonce)
    encrypted_data = aead.encrypt(plaintext, associated_data, 1)

    # associated_data mismatch
    assert_raises OpenSSL::Cipher::CipherError do
      aead.decrypt(encrypted_data, "mismatch!", 1)
    end

    # packet_number mismatch
    assert_raises OpenSSL::Cipher::CipherError do
      aead.decrypt(encrypted_data, associated_data, 2)
    end
  end
end
