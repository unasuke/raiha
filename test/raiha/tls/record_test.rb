require "test_helper"
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

  # @see https://datatracker.ietf.org/doc/html/rfc8448#section-3
  RFC8448_1RTT_SERVER_PROTECTED_HADSHAKE_RECORD = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    17 03 03 02 a2 d1 ff 33 4a 56 f5 bf
    f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e df
    78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45
    cb 96 0b 40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3
    89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b
    d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9
    b1 18 3e f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf
    51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d
    2e d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55
    cc 74 41 10 c4 53 ba a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f
    d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6
    86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac
    66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea
    52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e
    a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6
    54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb
    31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59
    62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e
    92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af
    36 87 90 18 e3 f2 52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37
    8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c
    f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6 6f 99 88
    2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa 80
    f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69
    18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99
    2f 67 f8 af e6 7f 76 91 3f a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11
    c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51
    56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42
    f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f
    60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd
    d5 02 78 40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af
    93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da
    bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b
  HEX

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

  def test_deserialize_tlsciphertext
    record = Raiha::TLS::Record.deserialize(RFC8448_1RTT_SERVER_PROTECTED_HADSHAKE_RECORD)
    assert_equal 1, record.length
    assert_equal Raiha::TLS::Record::TLSCiphertext, record[0].class
    assert_nil record[0].tls_inner_plaintext
  end
end
