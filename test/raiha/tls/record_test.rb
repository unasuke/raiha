require "test_helper"
require "support/rfc8448_test_vector"
require "raiha/tls/handshake"
require "raiha/tls/record"

class RaihaTLSRecordTest < Minitest::Test
  OPENSSL_HANDSHAKE_REPOSNSE_SAMPLE = [<<~SAMPLE.gsub(/[[:space:]]/, '')].pack("H*")
    16 03 03 00 7b 02 00 00 77 03 03 b9 8c 21 87 f7 0a 8a 14 7a cc b5 8c 05 d9 3f a6 23 ed 54 e4 bf e9 92 92 43 1c 9c 64 de
    e7 ee 74 00 13 01 00 00 4f 00 2b 00 02 03 04 00 33 00 45 00 17 00 41 04 a8 23 97 d3 35 47 92 b8 13 0c cf 09 5b 33 e4 e6
    9a 53 66 e0 0a cf e1 bd 2e fe e2 93 66 f6 b0 86 79 18 ef b7 1d 22 2f 3d 0c 64 15 d5 be 70 f2 ce 4e dd fc 82 b7 e8 f3 42
    d2 60 75 2e 35 98 0b 3e 14 03 03 00 01 01 17 03 03 00 31 77 50 0d 6c 22 b4 fb f9 80 e4 4e b1 26 f3 1f 2a c2 11 a7 a9 7e
    32 cb 03 8c f2 5a a3 79 6d 4d 32 f5 fd 61 d5 3d 12 0a 87 87 11 61 e1 1b 8f 40 59 81 17 03 03 02 f9 31 7c 7d 54 3f 72 a0
    b6 12 23 d0 3d 85 f9 9e ae 65 3f 10 60 1d b9 75 f5 b4 3f 73 77 55 4a 16 21 37 33 f4 97 46 7d d5 2b 37 68 8c 44 2a 0a 90
    f4 07 2d 9c e1 d3 80 f9 79 17 cb 94 6a fc 25 0b 7a 13 16 c9 ab 0a 7f 80 3b 52 2a 82 86 bb 82 1d ff 45 ee e2 2d 75 7f d8
    02 3b 56 e8 b6 14 da 2e d0 de c5 9f 81 fb 60 fb c3 51 08 8b da bd 37 4d 44 7d 86 b0 fe ca 09 8d d2 ec e2 4c f4 e2 a6 95
    d8 c7 4b 59 89 ae 8c 5b 91 c1 e3 12 60 dc 9a 6c d4 9a bb cb 70 fc 7f 83 3f 5c 81 e8 01 0b a1 18 16 88 ac 8a 0e fa 8c 50
    27 1d c7 a4 e6 ff e0 69 e1 da 0e 1c d2 07 f3 41 d5 ba d5 f2 28 3c 23 03 23 dc 01 b9 a4 31 ef a4 2c bd 0c 54 ca f0 5d 59
    66 a0 09 8a b0 06 99 a0 e3 8f cc 25 d3 af a4 b3 18 ba c7 88 c5 2f e0 88 aa 11 d5 4f b8 26 72 e7 79 9c 1d c4 87 52 c3 28
    68 1d 29 99 fb bb e8 01 d4 33 01 ee e9 19 6f ce 81 8e 29 3e e8 48 bc 58 a2 8d e2 1c b4 83 27 2f 5e f7 e8 a1 4d 92 ba e7
    ce 6b e3 ef fe 26 2e 38 40 5f f7 e1 4a cc 95 b0 98 bf 07 bc 52 16 cf c0 80 31 ce c9 24 d5 e0 6e 76 fa d8 ed 91 65 ae a4
    1a b9 6e 22 55 96 9f 4f ed 64 55 1c c8 3e 29 01 58 bc 4f 57 86 31 99 5a 80 6b 94 48 48 b3 ea 34 03 46 9d d7 4f 0e 1f 84
    a2 29 c2 b9 07 61 bd 2f 1b 99 3a 45 cc 60 7e eb d2 b9 fc 8c 4d 34 67 37 df 25 04 7a 6a b5 48 c8 e9 db ff ad 16 4a f7 8e
    0b 5a 0c 38 7f 97 cb 3d 68 e6 14 b3 8c ec 7a b0 56 13 a5 bd 19 61 96 33 03 4b 52 2c 9a df 05 67 fa 2e 79 c8 f0 60 54 f0
    9b b2 19 9b 35 97 01 10 c1 aa 54 cf 91 03 67 0c 4a 60 7b 28 10 d8 2a ca 2e 1f 14 e3 72 ce 5a a5 68 fc 50 b4 b7 3e 47 0e
    30 3e 8d b7 be 0e 87 58 a6 bd 82 81 80 5d ce aa f6 ff dd 96 4b 1b 7a 73 fe 4f 91 ba d0 4c cf 1f b8 41 7c 75 a2 a9 f4 a2
    11 13 8b e4 d8 aa 27 3b 41 db bd 65 97 64 fc a0 6f bb 03 a7 93 a3 51 6c a4 c2 51 bc 96 db 66 ef a6 48 f5 b9 bd b4 89 b9
    ea 86 78 9b cc 53 08 99 24 b3 16 da 17 c7 45 88 75 81 95 7c 10 d2 1d 3b 5d 8a 4c be 7d 07 44 e5 b5 8b 51 1e c9 f6 0f 53
    e3 c5 a1 30 ed f5 21 8e bc 01 24 cf 89 68 6f 70 ec a3 87 1e 66 6d 97 7f 3f bd 0e 2a 96 48 0e fb d9 9d 1a 9b 6c d6 d8 de
    da 23 c1 51 74 89 3c 9d 4c e1 41 fd ae 12 45 90 5e f2 c3 52 73 bf b2 37 7a f7 e1 42 26 49 f2 ed 6c 6b f2 3f 4c 13 51 67
    e8 a4 97 52 90 3f cb 88 9d e7 09 19 25 d1 4a 30 53 e1 d5 e4 d5 20 de c8 5f e4 71 76 ff 57 1f d4 5d 31 6d 32 f6 22 c6 7d
    ea 47 43 0b 00 47 a0 0e 3b 07 34 e0 ef 65 52 c4 c9 37 97 b9 91 73 b8 23 18 97 b8 56 da f1 85 50 3a 84 17 03 03 01 19 77
    29 cb ea de 04 21 7f ec 2e 5f 71 58 fe 0a 4e 3e 81 4b 88 26 52 af d1 18 8e 1d 24 d4 61 4a ff 8b a1 9d d9 ab d8 19 a5 c1
    aa c6 ad 58 0b b0 82 c6 a6 ce 02 97 d2 06 b9 3d 95 65 81 a5 26 a0 1f 6f 2b c6 bd 5b b2 b3 5c 2d 9b 0c e1 65 fa f6 2b 47
    d6 f9 e1 d9 65 79 d1 59 0e 7c fd 8c 40 7b e0 00 f7 f8 70 08 a5 92 09 69 d5 7f 6d 8e c2 71 15 06 b2 12 bb 81 89 43 a7 a4
    cf 2f c1 ed 38 1d 4d c8 e5 bd c8 ef de 5e db 8e 88 61 28 2b b7 b7 83 47 54 45 1c de c3 5c 29 aa 2b 9a 34 51 96 0b a0 00
    ed 67 af e1 70 29 6d dc 85 cc d3 25 c0 54 04 11 90 84 1a 13 7d 10 89 d8 4d 9a c0 be 70 b3 3a 0a 84 96 8e 9b 8f de a9 14
    40 4c e1 ab 64 7a 33 58 3e 9a 41 c5 47 96 85 a0 af e3 57 20 8d 88 07 6f 8e 0d 01 41 b5 13 b7 9d 3c 31 c9 0a 28 82 0a 00
    4b 8c 94 cb b3 a9 93 4b e3 d1 49 7d ce 1d a8 d6 84 af 93 25 de f8 95 e1 2b 7d f3 e2 d4 25 a5 1d 01 a1 e9 e1 db 7f dc 59
    17 03 03 00 35 63 db e8 a0 03 7f 22 c1 ba d5 aa 1d a1 90 42 eb e5 15 a8 4a 7a f5 1e 49 10 8b ce 21 7f 79 0d fa d8 aa 7f
    fb a6 37 97 69 fe be de ef 76 22 b1 87 77 b1 9b 4a 9d
  SAMPLE

  OPENSSL_HANDSHAKE_SAMPLE_CLIENT_HELLO = [<<~SAMPLE.gsub(/[[:space:]]/, '')].pack("H*")
    16 03 01 00 e5 01 00 00 e1 03 03 52 89 f8 e5 df c1 45 b0 ba
    70 be 82 c4 59 20 8a 12 f2 c6 a4 b1 ee 6a 2e 7c fa 94 e5 df
    1e b0 4e 20 38 9c 80 5c a2 47 05 67 8a 48 4e 48 3e d7 d6 43
    99 a8 68 2a 76 bc 0a 52 a5 17 d0 ff f7 0c cf bd 00 02 13 01
    01 00 00 96 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d
    00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23
    00 00 00 16 00 00 00 17 00 00 00 0d 00 24 00 22 04 03 05 03
    06 03 08 07 08 08 08 1a 08 1b 08 1c 08 09 08 0a 08 0b 08 04
    08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00
    02 01 01 00 33 00 26 00 24 00 1d 00 20 54 b2 82 f2 bd 56 15
    99 bc f3 65 54 8e b7 df ef e6 51 7c a5 6d bc 39 d8 b7 9a 29
    ad ad 25 d6 12 00 1b 00 05 04 00 01 00 03
  SAMPLE

  def test_tlsplaintext_serialize
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
    end
    record = Raiha::TLS::Record::TLSPlaintext.serialize(handshake)
    assert_equal 1, record.size
  end

  def test_tlsplaintext_serialize_require_fragment
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
      hs.message.extensions << Raiha::TLS::Handshake::Extension::Padding.generate_padding_with_length(16384)
    end
    record = Raiha::TLS::Record::TLSPlaintext.serialize(handshake)
    assert_equal 2, record.size
    assert_equal 16389, record[0].bytesize # limit of single TLSPlaintext struct
  end

  def test_tlsplaintext_unwrap_fragments
    # normal case
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
    end
    record = Raiha::TLS::Record::TLSPlaintext.serialize(handshake)
    fragments = Raiha::TLS::Record.unwrap_fragments(record[0])
    assert_equal String, fragments.first[:fragment].class

    # fragment size is too large
    assert_raises(RuntimeError) do
      fragments = Raiha::TLS::Record.unwrap_fragments(record[0] + "\x00")
    end

    # fragment size is too short
    assert_raises(RuntimeError) do
      fragments = Raiha::TLS::Record.unwrap_fragments(record[0][0..-2])
    end
  end

  def test_tlsplaintext_deserialize
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
    end
    record = Raiha::TLS::Record::TLSPlaintext.serialize(handshake)
    deserialized = Raiha::TLS::Record.deserialize(record.join)
    assert_equal 1, deserialized.length

    handshake2 = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
    end
    record2 = Raiha::TLS::Record::TLSPlaintext.serialize(handshake2)
    deserialized2 = Raiha::TLS::Record.deserialize(record.join + record2.join)
    assert_equal 2, deserialized2.length
    assert_equal Raiha::TLS::Record::TLSPlaintext, deserialized2[0].class
    assert_equal Raiha::TLS::Handshake, deserialized2[0].fragment.class
    assert_equal Raiha::TLS::Record::TLSPlaintext, deserialized2[1].class
    assert_equal Raiha::TLS::Handshake, deserialized2[1].fragment.class
  end

  def test_tlsplaintext_deserialize_openssl_sample
    record = Raiha::TLS::Record.deserialize(OPENSSL_HANDSHAKE_REPOSNSE_SAMPLE)
    assert_equal 6, record.length
    assert_equal Raiha::TLS::Record::TLSPlaintext, record[0].class
    assert_equal Raiha::TLS::Handshake::ServerHello, record[0].fragment.message.class
  end

  def test_tlsplaintext_deserialize_openssl_sample_client_hello
    record = Raiha::TLS::Record.deserialize(OPENSSL_HANDSHAKE_SAMPLE_CLIENT_HELLO)
    assert_equal 1, record.length
    assert_equal Raiha::TLS::Record::TLSPlaintext, record[0].class
    assert_equal Raiha::TLS::Handshake::ClientHello, record[0].fragment.message.class
    assert_equal_bin OPENSSL_HANDSHAKE_SAMPLE_CLIENT_HELLO, record[0].serialize
  end

  def test_deserialize_tlsciphertext
    record = Raiha::TLS::Record.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_PROTECTED_RECORD)
    assert_equal 1, record.length
    assert_equal Raiha::TLS::Record::TLSCiphertext, record[0].class
    assert_nil record[0].tls_inner_plaintext
  end
end
