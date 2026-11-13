# frozen_string_literal: true

# The samples of packet protection in RFC 9001 appendix A, "Sample Packet
# Protection". Every value is a frozen BINARY String, taken from
# rfcs/rfc9001.md.
module Raiha::QUIC::Test::Vectors
  # A.1 "Keys": the client chose this Destination Connection ID.
  module Keys
    DCID = ["8394c8f03e515708"].pack("H*").freeze
    INITIAL_SECRET = ["7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"].pack("H*").freeze
    CLIENT_INITIAL_SECRET = ["c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"].pack("H*").freeze
    CLIENT_KEY = ["1f369613dd76d5467730efcbe3b1a22d"].pack("H*").freeze
    CLIENT_IV = ["fa044b2f42a3fd3b46fb255c"].pack("H*").freeze
    CLIENT_HP = ["9f50449e04a0e810283a1e9933adedd2"].pack("H*").freeze
    SERVER_INITIAL_SECRET = ["3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"].pack("H*").freeze
    SERVER_KEY = ["cf3a5331653c364c88f0f379b6067e37"].pack("H*").freeze
    SERVER_IV = ["0ac1493ca1905853b0bba03e"].pack("H*").freeze
    SERVER_HP = ["c206b8d9b9f0f37644430b490eeaa314"].pack("H*").freeze
  end

  # A.2 "Client Initial": a CRYPTO frame padded to a 1,162-byte payload, in
  # packet number 2 with a 4-byte encoding.
  module ClientInitial
    PACKET_NUMBER = 2
    FRAMES = [<<~HEX.delete(" \n")].pack("H*").freeze
      06 00 40 f1 01 00 00 ed 03 03 eb f8 fa 56 f1 29
      39 b9 58 4a 38 96 47 2e c4 0b b8 63 cf d3 e8 68
      04 fe 3a 47 f0 6a 2b 69 48 4c 00 00 04 13 01 13
      02 01 00 00 c0 00 00 00 10 00 0e 00 00 0b 65 78
      61 6d 70 6c 65 2e 63 6f 6d ff 01 00 01 00 00 0a
      00 08 00 06 00 1d 00 17 00 18 00 10 00 07 00 05
      04 61 6c 70 6e 00 05 00 05 01 00 00 00 00 00 33
      00 26 00 24 00 1d 00 20 93 70 b2 c9 ca a4 7f ba
      ba f4 55 9f ed ba 75 3d e1 71 fa 71 f5 0f 1c e1
      5d 43 e9 94 ec 74 d7 48 00 2b 00 03 02 03 04 00
      0d 00 10 00 0e 04 03 05 03 06 03 02 03 08 04 08
      05 08 06 00 2d 00 02 01 01 00 1c 00 02 40 01 00
      39 00 32 04 08 ff ff ff ff ff ff ff ff 05 04 80
      00 ff ff 07 04 80 00 ff ff 08 01 10 01 04 80 00
      75 30 09 01 10 0f 08 83 94 c8 f0 3e 51 57 08 06
      04 80 00 ff ff
    HEX
    PAYLOAD_LENGTH = 1162
    HEADER = ["c300000001088394c8f03e5157080000449e00000002"].pack("H*").freeze
    SAMPLE = ["d1b1c98dd7689fb8ec11d242b123dc9b"].pack("H*").freeze
    MASK = ["437b9aec36"].pack("H*").freeze
    PROTECTED_HEADER = ["c000000001088394c8f03e5157080000449e7b9aec34"].pack("H*").freeze
    PACKET = [<<~HEX.delete(" \n")].pack("H*").freeze
      c0 00 00 00 01 08 83 94 c8 f0 3e 51 57 08 00 00
      44 9e 7b 9a ec 34 d1 b1 c9 8d d7 68 9f b8 ec 11
      d2 42 b1 23 dc 9b d8 ba b9 36 b4 7d 92 ec 35 6c
      0b ab 7d f5 97 6d 27 cd 44 9f 63 30 00 99 f3 99
      1c 26 0e c4 c6 0d 17 b3 1f 84 29 15 7b b3 5a 12
      82 a6 43 a8 d2 26 2c ad 67 50 0c ad b8 e7 37 8c
      8e b7 53 9e c4 d4 90 5f ed 1b ee 1f c8 aa fb a1
      7c 75 0e 2c 7a ce 01 e6 00 5f 80 fc b7 df 62 12
      30 c8 37 11 b3 93 43 fa 02 8c ea 7f 7f b5 ff 89
      ea c2 30 82 49 a0 22 52 15 5e 23 47 b6 3d 58 c5
      45 7a fd 84 d0 5d ff fd b2 03 92 84 4a e8 12 15
      46 82 e9 cf 01 2f 90 21 a6 f0 be 17 dd d0 c2 08
      4d ce 25 ff 9b 06 cd e5 35 d0 f9 20 a2 db 1b f3
      62 c2 3e 59 6d 11 a4 f5 a6 cf 39 48 83 8a 3a ec
      4e 15 da f8 50 0a 6e f6 9e c4 e3 fe b6 b1 d9 8e
      61 0a c8 b7 ec 3f af 6a d7 60 b7 ba d1 db 4b a3
      48 5e 8a 94 dc 25 0a e3 fd b4 1e d1 5f b6 a8 e5
      eb a0 fc 3d d6 0b c8 e3 0c 5c 42 87 e5 38 05 db
      05 9a e0 64 8d b2 f6 42 64 ed 5e 39 be 2e 20 d8
      2d f5 66 da 8d d5 99 8c ca bd ae 05 30 60 ae 6c
      7b 43 78 e8 46 d2 9f 37 ed 7b 4e a9 ec 5d 82 e7
      96 1b 7f 25 a9 32 38 51 f6 81 d5 82 36 3a a5 f8
      99 37 f5 a6 72 58 bf 63 ad 6f 1a 0b 1d 96 db d4
      fa dd fc ef c5 26 6b a6 61 17 22 39 5c 90 65 56
      be 52 af e3 f5 65 63 6a d1 b1 7d 50 8b 73 d8 74
      3e eb 52 4b e2 2b 3d cb c2 c7 46 8d 54 11 9c 74
      68 44 9a 13 d8 e3 b9 58 11 a1 98 f3 49 1d e3 e7
      fe 94 2b 33 04 07 ab f8 2a 4e d7 c1 b3 11 66 3a
      c6 98 90 f4 15 70 15 85 3d 91 e9 23 03 7c 22 7a
      33 cd d5 ec 28 1c a3 f7 9c 44 54 6b 9d 90 ca 00
      f0 64 c9 9e 3d d9 79 11 d3 9f e9 c5 d0 b2 3a 22
      9a 23 4c b3 61 86 c4 81 9e 8b 9c 59 27 72 66 32
      29 1d 6a 41 82 11 cc 29 62 e2 0f e4 7f eb 3e df
      33 0f 2c 60 3a 9d 48 c0 fc b5 69 9d bf e5 89 64
      25 c5 ba c4 ae e8 2e 57 a8 5a af 4e 25 13 e4 f0
      57 96 b0 7b a2 ee 47 d8 05 06 f8 d2 c2 5e 50 fd
      14 de 71 e6 c4 18 55 93 02 f9 39 b0 e1 ab d5 76
      f2 79 c4 b2 e0 fe b8 5c 1f 28 ff 18 f5 88 91 ff
      ef 13 2e ef 2f a0 93 46 ae e3 3c 28 eb 13 0f f2
      8f 5b 76 69 53 33 41 13 21 19 96 d2 00 11 a1 98
      e3 fc 43 3f 9f 25 41 01 0a e1 7c 1b f2 02 58 0f
      60 47 47 2f b3 68 57 fe 84 3b 19 f5 98 40 09 dd
      c3 24 04 4e 84 7a 4f 4a 0a b3 4f 71 95 95 de 37
      25 2d 62 35 36 5e 9b 84 39 2b 06 10 85 34 9d 73
      20 3a 4a 13 e9 6f 54 32 ec 0f d4 a1 ee 65 ac cd
      d5 e3 90 4d f5 4c 1d a5 10 b0 ff 20 dc c0 c7 7f
      cb 2c 0e 0e b6 05 cb 05 04 db 87 63 2c f3 d8 b4
      da e6 e7 05 76 9d 1d e3 54 27 01 23 cb 11 45 0e
      fc 60 ac 47 68 3d 7b 8d 0f 81 13 65 56 5f d9 8c
      4c 8e b9 36 bc ab 8d 06 9f c3 3b d8 01 b0 3a de
      a2 e1 fb c5 aa 46 3d 08 ca 19 89 6d 2b f5 9a 07
      1b 85 1e 6c 23 90 52 17 2f 29 6b fb 5e 72 40 47
      90 a2 18 10 14 f3 b9 4a 4e 97 d1 17 b4 38 13 03
      68 cc 39 db b2 d1 98 06 5a e3 98 65 47 92 6c d2
      16 2f 40 a2 9f 0c 3c 87 45 c0 f5 0f ba 38 52 e5
      66 d4 45 75 c2 9d 39 a0 3f 0c da 72 19 84 b6 f4
      40 59 1f 35 5e 12 d4 39 ff 15 0a ab 76 13 49 9d
      bd 49 ad ab c8 67 6e ef 02 3b 15 b6 5b fc 5c a0
      69 48 10 9f 23 f3 50 db 82 12 35 35 eb 8a 74 33
      bd ab cb 90 92 71 a6 ec bc b5 8b 93 6a 88 cd 4e
      8f 2e 6f f5 80 01 75 f1 13 25 3d 8f a9 ca 88 85
      c2 f5 52 e6 57 dc 60 3f 25 2e 1a 8e 30 8f 76 f0
      be 79 e2 fb 8f 5d 5f bb e2 e3 0e ca dd 22 07 23
      c8 c0 ae a8 07 8c df cb 38 68 26 3f f8 f0 94 00
      54 da 48 78 18 93 a7 e4 9a d5 af f4 af 30 0c d8
      04 a6 b6 27 9a b3 ff 3a fb 64 49 1c 85 19 4a ab
      76 0d 58 a6 06 65 4f 9f 44 00 e8 b3 85 91 35 6f
      bf 64 25 ac a2 6d c8 52 44 25 9f f2 b1 9c 41 b9
      f9 6f 3c a9 ec 1d de 43 4d a7 d2 d3 92 b9 05 dd
      f3 d1 f9 af 93 d1 af 59 50 bd 49 3f 5a a7 31 b4
      05 6d f3 1b d2 67 b6 b9 0a 07 98 31 aa f5 79 be
      0a 39 01 31 37 aa c6 d4 04 f5 18 cf d4 68 40 64
      7e 78 bf e7 06 ca 4c f5 e9 c5 45 3e 9f 7c fd 2b
      8b 4c 8d 16 9a 44 e5 5c 88 d4 a9 a7 f9 47 42 41
      e2 21 af 44 86 00 18 ab 08 56 97 2e 19 4c d9 34
    HEX
  end

  # A.3 "Server Initial": an ACK frame and a CRYPTO frame, no padding, in
  # packet number 1 with a 2-byte encoding.
  module ServerInitial
    PACKET_NUMBER = 1
    PAYLOAD = [<<~HEX.delete(" \n")].pack("H*").freeze
      02 00 00 00 00 06 00 40 5a 02 00 00 56 03 03 ee
      fc e7 f7 b3 7b a1 d1 63 2e 96 67 78 25 dd f7 39
      88 cf c7 98 25 df 56 6d c5 43 0b 9a 04 5a 12 00
      13 01 00 00 2e 00 33 00 24 00 1d 00 20 9d 3c 94
      0d 89 69 0b 84 d0 8a 60 99 3c 14 4e ca 68 4d 10
      81 28 7c 83 4d 53 11 bc f3 2b b9 da 1a 00 2b 00
      02 03 04
    HEX
    HEADER = ["c1000000010008f067a5502a4262b50040750001"].pack("H*").freeze
    SAMPLE = ["2cd0991cd25b0aac406a5816b6394100"].pack("H*").freeze
    MASK = ["2ec0d8356a"].pack("H*").freeze
    PROTECTED_HEADER = ["cf000000010008f067a5502a4262b5004075c0d9"].pack("H*").freeze
    PACKET = [<<~HEX.delete(" \n")].pack("H*").freeze
      cf 00 00 00 01 00 08 f0 67 a5 50 2a 42 62 b5 00
      40 75 c0 d9 5a 48 2c d0 99 1c d2 5b 0a ac 40 6a
      58 16 b6 39 41 00 f3 7a 1c 69 79 75 54 78 0b b3
      8c c5 a9 9f 5e de 4c f7 3c 3e c2 49 3a 18 39 b3
      db cb a3 f6 ea 46 c5 b7 68 4d f3 54 8e 7d de b9
      c3 bf 9c 73 cc 3f 3b de d7 4b 56 2b fb 19 fb 84
      02 2f 8e f4 cd d9 37 95 d7 7d 06 ed bb 7a af 2f
      58 89 18 50 ab bd ca 3d 20 39 8c 27 64 56 cb c4
      21 58 40 7d d0 74 ee
    HEX
  end

  # A.4 "Retry": in answer to the client Initial of A.2, whose Destination
  # Connection ID the tag covers but the packet does not carry.
  module Retry
    SOURCE_CONNECTION_ID = ["f067a5502a4262b5"].pack("H*").freeze
    TOKEN = "token".b.freeze
    PACKET = [<<~HEX.delete(" \n")].pack("H*").freeze
      ff 00 00 00 01 00 08 f0 67 a5 50 2a 42 62 b5 74
      6f 6b 65 6e 04 a2 65 ba 2e ff 4d 82 90 58 fb 3f
      0f 24 96 ba
    HEX
  end

  # A.5 "ChaCha20-Poly1305 Short Header Packet": a PING frame from a server,
  # with an empty Destination Connection ID, in packet number 654360564
  # encoded in 3 bytes.
  module ChaCha20ShortHeader
    SECRET = ["9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"].pack("H*").freeze
    KEY = ["c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"].pack("H*").freeze
    IV = ["e0459b3474bdd0e44a41c144"].pack("H*").freeze
    HP = ["25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"].pack("H*").freeze
    KU = ["1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"].pack("H*").freeze
    PACKET_NUMBER = 654_360_564
    NONCE = ["e0459b3474bdd0e46d417eb0"].pack("H*").freeze
    HEADER = ["4200bff4"].pack("H*").freeze
    PAYLOAD = ["01"].pack("H*").freeze
    CIPHERTEXT = ["655e5cd55c41f69080575d7999c25a5bfb"].pack("H*").freeze
    SAMPLE = ["5e5cd55c41f69080575d7999c25a5bfb"].pack("H*").freeze
    MASK = ["aefefe7d03"].pack("H*").freeze
    PROTECTED_HEADER = ["4cfe4189"].pack("H*").freeze
    PACKET = ["4cfe4189655e5cd55c41f69080575d7999c25a5bfb"].pack("H*").freeze
  end
end
