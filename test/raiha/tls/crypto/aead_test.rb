require "test_helper"
require "raiha/tls"
require "raiha/tls/test"

class RaihaTLSCryptoAEADTest < Minitest::Test
  AEAD = Raiha::TLS::Crypto::AEAD
  RFC8448 = Raiha::TLS::Test::RFC8448::Simple1RTT

  def hex(s) = [s.delete(" \n")].pack("H*")

  # RFC 8448 section 3: the server's first protected record, sequence 0, so
  # the nonce is the IV itself.
  def test_rfc8448_server_handshake_record
    aead = AEAD.new(:aes_128_gcm, RFC8448::SERVER_HANDSHAKE_WRITE_KEY)
    header = RFC8448::SERVER_HANDSHAKE_RECORD.byteslice(0, 5)
    body = RFC8448::SERVER_HANDSHAKE_RECORD.byteslice(5..)
    inner = RFC8448::ENCRYPTED_EXTENSIONS + RFC8448::CERTIFICATE + RFC8448::CERTIFICATE_VERIFY + RFC8448::SERVER_FINISHED + "\x16".b
    assert_equal_bin inner, aead.open(nonce: RFC8448::SERVER_HANDSHAKE_WRITE_IV, aad: header, ciphertext: body)
    assert_equal_bin body, AEAD.new(:aes_128_gcm, RFC8448::SERVER_HANDSHAKE_WRITE_KEY).seal(nonce: RFC8448::SERVER_HANDSHAKE_WRITE_IV, aad: header, plaintext: inner)
  end

  # RFC 8439 section 2.8.2.
  def test_rfc8439_chacha20_poly1305
    plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".b
    key = (0x80..0x9f).to_a.pack("C*")
    sealed = AEAD.new(:chacha20_poly1305, key).seal(nonce: hex("07000000 4041424344454647"), aad: hex("50515253 c0c1c2c3c4c5c6c7"), plaintext:)
    assert_equal_bin hex("d31a8d34648e60db7b86afbc53ef7ec2"), sealed.byteslice(0, 16)
    assert_equal_bin hex("1ae10b594f09e26a7e902ecbd0600691"), sealed.byteslice(-16, 16)
  end

  # McGrew and Viega, "The Galois/Counter Mode of Operation", test case 14.
  def test_aes_256_gcm_known_answer
    sealed = AEAD.new(:aes_256_gcm, "\x00".b * 32).seal(nonce: "\x00".b * 12, aad: "".b, plaintext: "\x00".b * 16)
    assert_equal_bin hex("cea7403d4d606b6e074ec5d3baf39d18 d0d1c8a799996bf0265b98b5d48ab919"), sealed
  end

  def test_round_trip_and_forgeries
    AEAD::CIPHERS.each_key do |algorithm|
      key = Random.new(1).bytes(algorithm == :aes_128_gcm ? 16 : 32)
      nonce = "\x01".b * 12
      sealer = AEAD.new(algorithm, key)
      opener = AEAD.new(algorithm, key)
      ["".b, "x".b, "y".b * 1000].each do |plaintext|
        sealed = sealer.seal(nonce:, aad: "aad", plaintext:)
        assert_equal plaintext.bytesize + AEAD::TAG_LENGTH, sealed.bytesize
        assert_equal_bin plaintext, opener.open(nonce:, aad: "aad", ciphertext: sealed)
        flipped = sealed.dup
        flipped.setbyte(0, flipped.getbyte(0) ^ 1)
        assert_nil opener.open(nonce:, aad: "aad", ciphertext: flipped), algorithm.to_s
        assert_nil opener.open(nonce:, aad: "aaD", ciphertext: sealed), algorithm.to_s
        assert_nil opener.open(nonce: "\x02".b * 12, aad: "aad", ciphertext: sealed), algorithm.to_s
        # A failed open leaves the context usable for the next record.
        assert_equal_bin plaintext, opener.open(nonce:, aad: "aad", ciphertext: sealed)
      end
      assert_nil opener.open(nonce:, aad: "", ciphertext: "\x00".b * (AEAD::TAG_LENGTH - 1))
    end
  end

  def test_unknown_algorithm
    assert_raises(ArgumentError) { AEAD.new(:aes_128_ccm, "\x00".b * 16) }
  end

  def test_the_key_stays_out_of_inspect_and_is_forgotten
    key = "\xab".b * 16
    aead = AEAD.new(:aes_128_gcm, key)
    refute_includes aead.inspect, "\xab".b.inspect[1..-2]
    refute_match(/@key/, aead.inspect)
    aead.discard!
    assert_equal "\xab".b * 16, key, "the caller's key is not touched"
    assert_empty aead.instance_variable_get(:@key)
  end
end
