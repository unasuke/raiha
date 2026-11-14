# frozen_string_literal: true

# Handshake messages, keys and secrets from RFC 8448, "Example Handshake
# Traces for TLS 1.3". Every value is a frozen BINARY String.
#
# Taken from rfcs/rfc8448.txt.
module Raiha::TLS::Test::RFC8448
  # The RSA key of the server's certificate in sections 3 to 5, from section
  # 2, as a PKCS #1 RSAPrivateKey in DER.
  SERVER_RSA_PRIVATE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
    30 82 02 5c 02 01 00 02 81 81 00 b4 bb 49 8f 82
    79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55
    e1 bd b8 26 d3 90 1a 24 61 ea fd 2d e4 9a 91 d0
    15 ab bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9 8c
    7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b
    01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43
    08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae
    8e a6 d1 d0 3e 2b d1 93 ef f0 ab 9a 80 02 c4 74
    28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01
    02 81 80 04 de a7 05 d4 3a 6e a7 20 9d d8 07 21
    11 a8 3c 81 e3 22 a5 92 78 b3 34 80 64 1e af 7c
    0a 69 85 b8 e3 1c 44 f6 de 62 e1 b4 c2 30 9f 61
    26 e7 7b 7c 41 e9 23 31 4b bf a3 88 13 05 dc 12
    17 f1 6c 81 9c e5 38 e9 22 f3 69 82 8d 0e 57 19
    5d 8c 84 88 46 02 07 b2 fa a7 26 bc f7 08 bb d7
    db 7f 67 9f 89 34 92 fc 2a 62 2e 08 97 0a ac 44
    1c e4 e0 c3 08 8d f2 5a e6 79 23 3d f8 a3 bd a2
    ff 99 41 02 41 00 e4 35 fb 7c c8 37 37 75 6d ac
    ea 96 ab 7f 59 a2 cc 10 69 db 7d eb 19 0e 17 e3
    3a 53 2b 27 3f 30 a3 27 aa 0a aa bc 58 cd 67 46
    6a f9 84 5f ad c6 75 fe 09 4a f9 2c 4b d1 f2 c1
    bc 33 dd 2e 05 15 02 41 00 ca bd 3b c0 e0 43 86
    64 c8 d4 cc 9f 99 97 7a 94 d9 bb fe ad 8e 43 87
    0a ba e3 f7 eb 8b 4e 0e ee 8a f1 d9 b4 71 9b a6
    19 6c f2 cb ba ee eb f8 b3 49 0a fe 9e 9f fa 74
    a8 8a a5 1f c6 45 62 93 03 02 40 3f 57 34 5c 27
    fe 1b 68 7e 6e 76 16 27 b7 8b 1b 82 64 33 dd 76
    0f a0 be a6 a6 ac f3 94 90 aa 1b 47 cd a4 86 9d
    68 f5 84 dd 5b 50 29 bd 32 09 3b 82 58 66 1f e7
    15 02 5e 5d 70 a4 5a 08 d3 d3 19 02 40 18 3d a0
    13 63 bd 2f 28 85 ca cb dc 99 64 bf 47 64 f1 51
    76 36 f8 64 01 28 6f 71 89 3c 52 cc fe 40 a6 c2
    3d 0d 08 6b 47 c6 fb 10 d8 fd 10 41 e0 4d ef 7e
    9a 40 ce 95 7c 41 77 94 e1 04 12 d1 39 02 41 00
    83 9c a9 a0 85 e4 28 6b 2c 90 e4 66 99 7a 2c 68
    1f 21 33 9a a3 47 78 14 e4 de c1 18 33 05 0e d5
    0d d1 3c c0 38 04 8a 43 c5 9b 2a cc 41 68 89 c0
    37 66 5f e5 af a6 05 96 9f 8c 01 df a5 ca 96 9d
  HEX

  # RFC 8448 §3, Simple 1-RTT Handshake.
  module Simple1RTT
    CLIENT_X25519_PRIVATE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca
      a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05
    HEX

    CLIENT_X25519_PUBLIC_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe
      b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c
    HEX

    CLIENT_HELLO = [<<~HEX.delete(" \n")].pack("H*").freeze
      01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38
      c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef
      62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01
      00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76
      65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00
      17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00
      23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
      e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e
      51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00
      03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
      02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01
      04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c
      00 02 40 01
    HEX

    CLIENT_HELLO_RANDOM = [<<~HEX.delete(" \n")].pack("H*").freeze
      cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d
      ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7
    HEX

    SERVER_X25519_PRIVATE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56 52 57 8c
      c8 10 e9 98 01 91 ec 8d 05 83 08 ce a2 16 a2 1e
    HEX

    SERVER_X25519_PUBLIC_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1
      56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f
    HEX

    SERVER_HELLO = [<<~HEX.delete(" \n")].pack("H*").freeze
      02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e
      60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55
      77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24
      00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db
      f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0
      4e 75 1f 0f 00 2b 00 02 03 04
    HEX

    # "tls13 derived", the salt for the handshake secret.
    DERIVED_SECRET_FOR_HANDSHAKE = [<<~HEX.delete(" \n")].pack("H*").freeze
      6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97
      16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba
    HEX

    # The X25519 shared secret.
    HANDSHAKE_IKM = [<<~HEX.delete(" \n")].pack("H*").freeze
      8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
      35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d
    HEX

    CLIENT_HANDSHAKE_TRAFFIC_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f
      3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21
    HEX

    SERVER_HANDSHAKE_TRAFFIC_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4
      e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38
    HEX

    SERVER_HANDSHAKE_WRITE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc
    HEX

    SERVER_HANDSHAKE_WRITE_IV = [<<~HEX.delete(" \n")].pack("H*").freeze
      5d 31 3e b2 67 12 76 ee 13 00 0b 30
    HEX

    ENCRYPTED_EXTENSIONS = [<<~HEX.delete(" \n")].pack("H*").freeze
      08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17
      00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
      00 02 40 01 00 00 00 00
    HEX

    CERTIFICATE = [<<~HEX.delete(" \n")].pack("H*").freeze
      0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30
      82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a
      86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a
      06 03 55 04 03 13 03 72 73 61 30 1e 17 0d 31 36
      30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36 30
      37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a
      06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06
      09 2a 86 48 86 f7 0d 01 01 01 05 00 03 81 8d 00
      30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98
      08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
      d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a
      95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12
      09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b
      63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80
      30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0
      3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a
      8d 88 d7 9f 7f 1e 3f 02 03 01 00 01 a3 1a 30 18
      30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55
      1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86
      f7 0d 01 01 0b 05 00 03 81 81 00 85 aa d2 a0 e5
      b9 27 6b 90 8c 65 f7 3a 72 67 17 06 18 a5 4c 5f
      8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5
      8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a
      03 01 51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02
      70 2e 60 8c ca e6 be c1 fc 63 a4 2a 99 be 5c 3e
      b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84 e0
      a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8
      f8 96 12 29 ac 91 87 b4 2b 4d e1 00 00
    HEX

    CERTIFICATE_VERIFY = [<<~HEX.delete(" \n")].pack("H*").freeze
      0f 00 00 84 08 04 00 80 5a 74 7c 5d 88 fa 9b d2
      e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
      b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3
      3a 5c 14 1a 07 86 53 fa 6b ef 78 0c 5e a2 48 ee
      aa a7 85 c4 f3 94 ca b6 d3 0b be 8d 48 59 ee 51
      1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c
      9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09
      d3 be 15 2a 3d a5 04 3e 06 3d da 65 cd f5 ae a2
      0d 53 df ac d4 2f 74 f3
    HEX

    SERVER_FINISHED = [<<~HEX.delete(" \n")].pack("H*").freeze
      14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7
      1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54
      b7 8f 07 18
    HEX

    # The protected record carrying EncryptedExtensions to Finished.
    SERVER_HANDSHAKE_RECORD = [<<~HEX.delete(" \n")].pack("H*").freeze
      17 03 03 02 a2 d1 ff 33 4a 56 f5 bf f6 59 4a 07
      cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e
      df 78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca
      07 61 2e f9 f9 45 cb 96 0b 40 68 90 51 23 ea 78
      b1 11 b4 29 ba 91 91 cd 05 d2 a3 89 28 0f 52 61
      34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b
      d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79
      02 07 16 cf b9 b1 18 3e f3 ab 20 e3 7d 57 a6 b9
      d7 47 76 09 ae e6 e1 22 a4 cf 51 42 73 25 25 0c
      7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d 2e
      d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3
      60 98 72 55 cc 74 41 10 c4 53 ba a4 fc d6 10 92
      8d 80 98 10 e4 b7 ed 1a 8f d9 91 f0 6a a6 24 82
      04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6 86 94
      5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8
      94 41 ac 66 27 2f d8 fb 33 0e f8 19 05 79 b3 68
      45 96 c9 60 bd 59 6e ea 52 0a 56 a8 d6 50 f5 63
      aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e a5 e2 2f
      44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26
      4e d6 54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26
      f5 9e ca ba 9a cb bb 31 7b 66 d9 02 f4 f2 92 a3
      6a c1 b6 39 c6 37 ce 34 31 17 b6 59 62 22 45 31
      7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64
      7e 92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e
      1b 7a 6c 71 78 af 36 87 90 18 e3 f2 52 10 7f 24
      3d 24 3d c7 33 9d 56 84 c8 b0 37 8b f3 02 44 da
      8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c
      f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4
      61 e6 6f 99 88 2b d8 9f c5 08 00 be cc a6 2d 6c
      74 11 6d bd 29 72 fd a1 fa 80 f8 5d f8 81 ed be
      5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69 18
      a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb
      99 2f 2b 99 2f 67 f8 af e6 7f 76 91 3f a3 88 cb
      56 30 c8 ca 01 e0 c6 5d 11 c6 6a 1e 2a c4 c8 59
      77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51 56 14
      63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38
      eb ba 42 f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97
      8c 31 7f c9 fa 66 a7 3f 60 f0 50 4d e9 3b 5b 84
      5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd d5 02 78
      40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5
      d2 af 93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31
      ed e4 2c 17 19 bf da bf 02 53 fe 51 75 be 89 8e
      75 0e dc 53 37 0d 2b
    HEX

    CLIENT_APPLICATION_TRAFFIC_SECRET_0 = [<<~HEX.delete(" \n")].pack("H*").freeze
      9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52
      87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5
    HEX

    SERVER_APPLICATION_TRAFFIC_SECRET_0 = [<<~HEX.delete(" \n")].pack("H*").freeze
      a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32
      82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43
    HEX

    SERVER_APPLICATION_WRITE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56
    HEX

    SERVER_APPLICATION_WRITE_IV = [<<~HEX.delete(" \n")].pack("H*").freeze
      cf 78 2b 88 dd 83 54 9a ad f1 e9 84
    HEX

    CLIENT_FINISHED = [<<~HEX.delete(" \n")].pack("H*").freeze
      14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a c1 fc
      eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2
      ed d5 ce 61
    HEX

    # The protected record carrying the client Finished.
    CLIENT_FINISHED_RECORD = [<<~HEX.delete(" \n")].pack("H*").freeze
      17 03 03 00 35 75 ec 4d c2 38 cc e6 0b 29 80 44
      a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc
      44 d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c
      ae ac ab 68 67 d7 26 c4 05 46
    HEX

    CLIENT_APPLICATION_WRITE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51
    HEX

    CLIENT_APPLICATION_WRITE_IV = [<<~HEX.delete(" \n")].pack("H*").freeze
      5b 78 92 3d ee 08 57 90 33 e5 23 d9
    HEX

    NEW_SESSION_TICKET = [<<~HEX.delete(" \n")].pack("H*").freeze
      04 00 00 c9 00 00 00 1e fa d6 aa c5 02 00 00 00
      b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00
      00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf
      1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a
      bc 55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1
      43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28 27
      db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2
      9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29
      51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28
      bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6 17 64
      6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f
      7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a
      e4 d3 57 00 08 00 2a 00 04 00 00 04 00
    HEX

    # The records after the handshake, each under the sender's first
    # application traffic key: the server's NewSessionTicket, then these 50
    # bytes each way, then close_notify each way.
    APPLICATION_DATA = (0x00..0x31).to_a.pack("C*").freeze

    NEW_SESSION_TICKET_RECORD = [<<~HEX.delete(" \n")].pack("H*").freeze
      17 03 03 00 de 3a 6b 8f 90 41 4a 97 d6 95 9c 34
      87 68 0d e5 13 4a 2b 24 0e 6c ff ac 11 6e 95 d4
      1d 6a f8 f6 b5 80 dc f3 d1 1d 63 c7 58 db 28 9a
      01 59 40 25 2f 55 71 3e 06 1d c1 3e 07 88 91 a3
      8e fb cf 57 53 ad 8e f1 70 ad 3c 73 53 d1 6d 9d
      a7 73 b9 ca 7f 2b 9f a1 b6 c0 d4 a3 d0 3f 75 e0
      9c 30 ba 1e 62 97 2a c4 6f 75 f7 b9 81 be 63 43
      9b 29 99 ce 13 06 46 15 13 98 91 d5 e4 c5 b4 06
      f1 6e 3f c1 81 a7 7c a4 75 84 00 25 db 2f 0a 77
      f8 1b 5a b0 5b 94 c0 13 46 75 5f 69 23 2c 86 51
      9d 86 cb ee ac 87 aa c3 47 d1 43 f9 60 5d 64 f6
      50 db 4d 02 3e 70 e9 52 ca 49 fe 51 37 12 1c 74
      bc 26 97 68 7e 24 87 46 d6 df 35 30 05 f3 bc e1
      86 96 12 9c 81 53 55 6b 3b 6c 67 79 b3 7b f1 59
      85 68 4f
    HEX

    CLIENT_APPLICATION_DATA_RECORD = [<<~HEX.delete(" \n")].pack("H*").freeze
      17 03 03 00 43 a2 3f 70 54 b6 2c 94 d0 af fa fe
      82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f
      2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b
      62 97 4e 1f 5a 62 92 a2 97 70 14 bd 1e 3d ea e6
      3a ee bb 21 69 49 15 e4
    HEX

    SERVER_APPLICATION_DATA_RECORD = [<<~HEX.delete(" \n")].pack("H*").freeze
      17 03 03 00 43 2e 93 7e 11 ef 4a c7 40 e5 38 ad
      36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b 36
      e3 0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8
      fc c4 9c 4b f2 e5 f0 a2 1c 00 47 c2 ab f3 32 54
      0d d0 32 e1 67 c2 95 5d
    HEX

    CLIENT_ALERT_RECORD = [<<~HEX.delete(" \n")].pack("H*").freeze
      17 03 03 00 13 c9 87 27 60 65 56 66 b7 4d 7f f1
      15 3e fd 6d b6 d0 b0 e3
    HEX

    SERVER_ALERT_RECORD = [<<~HEX.delete(" \n")].pack("H*").freeze
      17 03 03 00 13 b5 8f d6 71 66 eb f5 99 d2 47 20
      cf be 7e fa 7a 88 64 a9
    HEX

    EARLY_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2
      10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a
    HEX

    # The hash of an empty string, the context of each "derived" step.
    EMPTY_HASH = [<<~HEX.delete(" \n")].pack("H*").freeze
      e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
      27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55
    HEX

    HANDSHAKE_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01
      04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac
    HEX

    # The transcript hash over ClientHello and ServerHello.
    HELLO_TRANSCRIPT_HASH = [<<~HEX.delete(" \n")].pack("H*").freeze
      86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
      d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8
    HEX

    # "tls13 derived", the salt for the main secret.
    DERIVED_SECRET_FOR_MAIN = [<<~HEX.delete(" \n")].pack("H*").freeze
      43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5
      31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4
    HEX

    MAIN_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47
      80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19
    HEX

    SERVER_FINISHED_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f
      c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8
    HEX

    # The transcript hash from ClientHello through the server Finished.
    SERVER_FINISHED_TRANSCRIPT_HASH = [<<~HEX.delete(" \n")].pack("H*").freeze
      96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a
      00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13
    HEX

    EXPORTER_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67 92 c5
      0c 9a 3f 89 45 2f 68 d8 ae 31 1b 43 09 d3 cf 50
    HEX

    CLIENT_HANDSHAKE_WRITE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01
    HEX

    CLIENT_HANDSHAKE_WRITE_IV = [<<~HEX.delete(" \n")].pack("H*").freeze
      5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f
    HEX

    CLIENT_FINISHED_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d 6b f8
      3f 84 82 1d 1f 87 fd c7 d3 c7 5b 5a 7b 42 d9 c4
    HEX

    # The transcript hash from ClientHello through the client Finished.
    CLIENT_FINISHED_TRANSCRIPT_HASH = [<<~HEX.delete(" \n")].pack("H*").freeze
      20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26
      84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d
    HEX

    RESUMPTION_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf
      da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c
    HEX

    # The PSK of the NewSessionTicket, whose ticket_nonce is 00 00.
    TICKET_PSK = [<<~HEX.delete(" \n")].pack("H*").freeze
      4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5
      85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3
    HEX
  end

  # RFC 8448 §4, Resumed 0-RTT Handshake.
  module Resumed0RTT
    CLIENT_HELLO = [<<~HEX.delete(" \n")].pack("H*").freeze
      01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff 93 83
      55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41
      9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01
      00 01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76
      65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00
      17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00
      33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d
      96 c9 9d a2 66 98 34 6c 6b e1 64 82 ba dd da fe
      05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00 00 00 2b 00
      03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
      02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01
      04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c
      00 02 40 01 00 15 00 57 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7
      af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a
      34 cb 33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36
      7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11
      72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61
      be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3
      66 4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc
      67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c 5b
      3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2
      97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6
      21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33
      43 69 40 93 93 4a e4 d3 57 fa d6 aa cb 00 21 20
      3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8
      8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d
    HEX

    # CLIENT_HELLO up to, but not including, the binders: the input to the binder.
    CLIENT_HELLO_PREFIX = [<<~HEX.delete(" \n")].pack("H*").freeze
      01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff 93 83
      55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41
      9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01
      00 01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76
      65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00
      17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00
      33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d
      96 c9 9d a2 66 98 34 6c 6b e1 64 82 ba dd da fe
      05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00 00 00 2b 00
      03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
      02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01
      04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c
      00 02 40 01 00 15 00 57 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7
      af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a
      34 cb 33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36
      7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11
      72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61
      be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3
      66 4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc
      67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c 5b
      3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2
      97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6
      21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33
      43 69 40 93 93 4a e4 d3 57 fa d6 aa cb
    HEX

    SERVER_HELLO = [<<~HEX.delete(" \n")].pack("H*").freeze
      02 00 00 5c 03 03 3c cf d2 de c8 90 22 27 63 47
      2a e8 13 67 77 c9 d7 35 87 77 bb 66 e9 1e a5 12
      24 95 f5 59 ea 2d 00 13 01 00 00 34 00 29 00 02
      00 00 00 33 00 24 00 1d 00 20 12 17 61 ee 42 c3
      33 e1 b9 e7 7b 60 dd 57 c2 05 3c d9 45 12 ab 47
      f1 15 e8 6e ff 50 94 2c ea 31 00 2b 00 02 03 04
    HEX

    # The values of the client's side, for its role.
    CLIENT_X25519_PRIVATE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      bf f9 11 88 28 38 46 dd 6a 21 34 ef 71 80 ca 2b
      0b 14 fb 10 dc e7 07 b5 09 8c 0d dd c8 13 b2 df
    HEX

    CLIENT_EARLY_TRAFFIC_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e ff 7e
      aa 10 10 55 86 e7 be 5c 09 67 8d 63 b6 ca ab 62
    HEX

    CLIENT_HANDSHAKE_TRAFFIC_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      2f aa c0 8f 85 1d 35 fe a3 60 4f cb 4d e8 2d c6
      2c 9b 16 4a 70 97 4d 04 62 e2 7f 1a b2 78 70 0f
    HEX

    SERVER_HANDSHAKE_TRAFFIC_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      fe 92 7a e2 71 31 2e 8b f0 27 5b 58 1c 54 ee f0
      20 45 0d c4 ec ff aa 05 a1 a3 5d 27 51 8e 78 03
    HEX

    CLIENT_APPLICATION_TRAFFIC_SECRET_0 = [<<~HEX.delete(" \n")].pack("H*").freeze
      2a bb f2 b8 e3 81 d2 3d be be 1d d2 a7 d1 6a 8b
      f4 84 cb 49 50 d2 3f b7 fb 7f a8 54 70 62 d9 a1
    HEX

    SERVER_APPLICATION_TRAFFIC_SECRET_0 = [<<~HEX.delete(" \n")].pack("H*").freeze
      cc 21 f1 bf 8f eb 7d d5 fa 50 5b d9 c4 b4 68 a9
      98 4d 55 4a 99 3d c4 9e 6d 28 55 98 fb 67 26 91
    HEX

    # NSS's EncryptedExtensions, taking 0-RTT.
    ENCRYPTED_EXTENSIONS = [<<~HEX.delete(" \n")].pack("H*").freeze
      08 00 00 28 00 26 00 0a 00 14 00 12 00 1d 00 17
      00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
      00 02 40 01 00 00 00 00 00 2a 00 00
    HEX

    SERVER_FINISHED = [<<~HEX.delete(" \n")].pack("H*").freeze
      14 00 00 20 48 d3 e0 e1 b3 d9 07 c6 ac ff 14 5e
      16 09 03 88 c7 7b 05 c0 50 b6 34 ab 1a 88 bb d0
      dd 1a 34 b2
    HEX

    END_OF_EARLY_DATA = [<<~HEX.delete(" \n")].pack("H*").freeze
      05 00 00 00
    HEX

    CLIENT_FINISHED = [<<~HEX.delete(" \n")].pack("H*").freeze
      14 00 00 20 72 30 a9 c9 52 c2 5c d6 13 8f c5 e6
      62 83 08 c4 1c 53 35 dd 81 b9 f9 6b ce a5 0f d3
      2b da 41 6d
    HEX
  end

  # RFC 8448 §5, HelloRetryRequest.
  module HelloRetryRequest
    CLIENT_HELLO_1 = [<<~HEX.delete(" \n")].pack("H*").freeze
      01 00 00 b0 03 03 b0 b1 c5 a5 aa 37 c5 91 9f 2e
      d1 d5 c6 ff f7 fc b7 84 97 16 94 5a 2b 8c ee 92
      58 a3 46 67 7b 6f 00 00 06 13 01 13 03 13 02 01
      00 00 81 00 00 00 0b 00 09 00 00 06 73 65 72 76
      65 72 ff 01 00 01 00 00 0a 00 08 00 06 00 1d 00
      17 00 18 00 33 00 26 00 24 00 1d 00 20 e8 e8 e3
      f3 b9 3a 25 ed 97 a1 4a 7d ca cb 8a 27 2c 62 88
      e5 85 c6 48 4d 05 26 2f ca d0 62 ad 1f 00 2b 00
      03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
      02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01
      04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c
      00 02 40 01
    HEX

    HELLO_RETRY_REQUEST = [<<~HEX.delete(" \n")].pack("H*").freeze
      02 00 00 ac 03 03 cf 21 ad 74 e5 9a 61 11 be 1d
      8c 02 1e 65 b8 91 c2 a2 11 16 7a bb 8c 5e 07 9e
      09 e2 c8 a8 33 9c 00 13 01 00 00 84 00 33 00 02
      00 17 00 2c 00 74 00 72 71 dc d0 4b b8 8b c3 18
      91 19 39 8a 00 00 00 00 ee fa fc 76 c1 46 b8 23
      b0 96 f8 aa ca d3 65 dd 00 30 95 3f 4e df 62 56
      36 e5 f2 1b b2 e2 3f cc 65 4b 1b 5b 40 31 8d 10
      d1 37 ab cb b8 75 74 e3 6e 8a 1f 02 5f 7d fa 5d
      6e 50 78 1b 5e da 4a a1 5b 0c 8b e7 78 25 7d 16
      aa 30 30 e9 e7 84 1d d9 e4 c0 34 22 67 e8 ca 0c
      af 57 1f b2 b7 cf f0 f9 34 b0 00 2b 00 02 03 04
    HEX

    CLIENT_HELLO_2 = [<<~HEX.delete(" \n")].pack("H*").freeze
      01 00 01 fc 03 03 b0 b1 c5 a5 aa 37 c5 91 9f 2e
      d1 d5 c6 ff f7 fc b7 84 97 16 94 5a 2b 8c ee 92
      58 a3 46 67 7b 6f 00 00 06 13 01 13 03 13 02 01
      00 01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76
      65 72 ff 01 00 01 00 00 0a 00 08 00 06 00 1d 00
      17 00 18 00 33 00 47 00 45 00 17 00 41 04 a6 da
      73 92 ec 59 1e 17 ab fd 53 59 64 b9 98 94 d1 3b
      ef b2 21 b3 de f2 eb e3 83 0e ac 8f 01 51 81 26
      77 c4 d6 d2 23 7e 85 cf 01 d6 91 0c fb 83 95 4e
      76 ba 73 52 83 05 34 15 98 97 e8 06 57 80 00 2b
      00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06
      03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
      01 04 02 05 02 06 02 02 02 00 2c 00 74 00 72 71
      dc d0 4b b8 8b c3 18 91 19 39 8a 00 00 00 00 ee
      fa fc 76 c1 46 b8 23 b0 96 f8 aa ca d3 65 dd 00
      30 95 3f 4e df 62 56 36 e5 f2 1b b2 e2 3f cc 65
      4b 1b 5b 40 31 8d 10 d1 37 ab cb b8 75 74 e3 6e
      8a 1f 02 5f 7d fa 5d 6e 50 78 1b 5e da 4a a1 5b
      0c 8b e7 78 25 7d 16 aa 30 30 e9 e7 84 1d d9 e4
      c0 34 22 67 e8 ca 0c af 57 1f b2 b7 cf f0 f9 34
      b0 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00
      af 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    HEX

    SERVER_HELLO = [<<~HEX.delete(" \n")].pack("H*").freeze
      02 00 00 77 03 03 bb 34 1d 84 7f d7 89 c4 7c 38
      71 72 dc 0c 9b f1 47 fc ca cb 50 43 d8 6c a4 c5
      98 d3 ff 57 1b 98 00 13 01 00 00 4f 00 33 00 45
      00 17 00 41 04 58 3e 05 4b 7a 66 67 2a e0 20 ad
      9d 26 86 fc c8 5b 5a d4 1a 13 4a 0f 03 ee 72 b8
      93 05 2b d8 5b 4c 8d e6 77 6f 5b 04 ac 07 d8 35
      40 ea b3 e3 d9 c5 47 bc 65 28 c4 31 7d 29 46 86
      09 3a 6c ad 7d 00 2b 00 02 03 04
    HEX

    # The transcript hash over message_hash(ClientHello1), HelloRetryRequest, ClientHello2 and ServerHello.
    HELLO_TRANSCRIPT_HASH = [<<~HEX.delete(" \n")].pack("H*").freeze
      8a a8 e8 28 ec 2f 8a 88 4f ec 95 a3 13 9d e0 1c
      15 a3 da a7 ff 5b fc 3f 4b fc c2 1b 43 8d 7b f8
    HEX

    # The transcript hash from message_hash(ClientHello1) through the server Finished.
    SERVER_FINISHED_TRANSCRIPT_HASH = [<<~HEX.delete(" \n")].pack("H*").freeze
      50 f6 3c bf 36 b0 dd 04 9e 7a 0b a2 7d 64 55 74
      5e a2 aa ac 54 bb 16 7f 99 50 b2 b7 ce 95 09 da
    HEX

    ENCRYPTED_EXTENSIONS = [<<~HEX.delete(" \n")].pack("H*").freeze
      08 00 00 18 00 16 00 0a 00 08 00 06 00 17 00 18
      00 1d 00 1c 00 02 40 01 00 00 00 00
    HEX

    CERTIFICATE = [<<~HEX.delete(" \n")].pack("H*").freeze
      0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30
      82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a
      86 48 86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a
      06 03 55 04 03 13 03 72 73 61 30 1e 17 0d 31 36
      30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36 30
      37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a
      06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06
      09 2a 86 48 86 f7 0d 01 01 01 05 00 03 81 8d 00
      30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 3d 98
      08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
      d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a
      95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12
      09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b
      63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80
      30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0
      3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a
      8d 88 d7 9f 7f 1e 3f 02 03 01 00 01 a3 1a 30 18
      30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55
      1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86
      f7 0d 01 01 0b 05 00 03 81 81 00 85 aa d2 a0 e5
      b9 27 6b 90 8c 65 f7 3a 72 67 17 06 18 a5 4c 5f
      8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5
      8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a
      03 01 51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02
      70 2e 60 8c ca e6 be c1 fc 63 a4 2a 99 be 5c 3e
      b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84 e0
      a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8
      f8 96 12 29 ac 91 87 b4 2b 4d e1 00 00
    HEX

    CERTIFICATE_VERIFY = [<<~HEX.delete(" \n")].pack("H*").freeze
      0f 00 00 84 08 04 00 80 33 ab 13 d4 46 27 07 23
      1b 5d ca e6 c8 19 0b 63 d1 da bc 74 f2 8c 39 53
      70 da 0b 07 e5 b8 30 66 d0 24 6a 31 ac d9 5d f4
      75 bf d7 99 a4 a7 0d 33 ad 93 d3 a3 17 a9 b2 c0
      d2 37 a5 68 5b 21 9e 77 41 12 e3 91 a2 47 60 7d
      1a ef f1 bb d0 a3 9f 38 2e e1 a5 fe 88 ae 99 ec
      59 22 8e 64 97 e4 5d 48 ce 27 5a 6d 5e f4 0d 16
      9f b6 f9 d3 3b 05 2e d3 dc dd 6b 5a 48 ba af ff
      bc b2 90 12 84 15 bd 38
    HEX

    SERVER_FINISHED = [<<~HEX.delete(" \n")].pack("H*").freeze
      14 00 00 20 88 63 e6 bf b0 42 0a 92 7f a2 7f 34
      33 6a 70 ae 42 6e 96 8e 3e b8 84 94 5b 96 85 6d
      ba 39 76 d1
    HEX

    CLIENT_X25519_PRIVATE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      0e d0 2f 8e 81 17 ef c7 5c a7 ac 32 aa 7e 34 ed
      a6 4c dc 0d da d1 54 a5 e8 52 89 f9 59 f6 32 04
    HEX

    CLIENT_X25519_PUBLIC_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      e8 e8 e3 f3 b9 3a 25 ed 97 a1 4a 7d ca cb 8a 27
      2c 62 88 e5 85 c6 48 4d 05 26 2f ca d0 62 ad 1f
    HEX

    CLIENT_SECP256R1_PRIVATE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      ab 54 73 46 7e 19 34 6c eb 0a 04 14 e4 1d a2 1d
      4d 24 45 bc 30 25 af e9 7c 4e 8d c8 d5 13 da 39
    HEX

    CLIENT_SECP256R1_PUBLIC_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      04 a6 da 73 92 ec 59 1e 17 ab fd 53 59 64 b9 98
      94 d1 3b ef b2 21 b3 de f2 eb e3 83 0e ac 8f 01
      51 81 26 77 c4 d6 d2 23 7e 85 cf 01 d6 91 0c fb
      83 95 4e 76 ba 73 52 83 05 34 15 98 97 e8 06 57
      80
    HEX

    SERVER_SECP256R1_PRIVATE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      8c 51 06 01 f9 76 5b fb 8e d6 93 44 9a 48 98 98
      59 b5 cf a8 79 cb 9f 54 43 c4 1c 5f f1 06 34 ed
    HEX

    SERVER_SECP256R1_PUBLIC_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      04 58 3e 05 4b 7a 66 67 2a e0 20 ad 9d 26 86 fc
      c8 5b 5a d4 1a 13 4a 0f 03 ee 72 b8 93 05 2b d8
      5b 4c 8d e6 77 6f 5b 04 ac 07 d8 35 40 ea b3 e3
      d9 c5 47 bc 65 28 c4 31 7d 29 46 86 09 3a 6c ad
      7d
    HEX

    # The P-256 shared secret.
    HANDSHAKE_IKM = [<<~HEX.delete(" \n")].pack("H*").freeze
      c1 42 ce 13 ca 11 b5 c2 23 36 52 e6 3a d3 d9 78
      44 f1 62 1f bf b9 de 69 d5 47 dc 8f ed ea be b4
    HEX

    CLIENT_HANDSHAKE_TRAFFIC_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      15 8a a7 ab 88 55 07 35 82 b4 1d 67 4b 40 55 ca
      bc c5 34 72 8f 65 93 14 86 1b 4e 08 e2 01 15 66
    HEX

    SERVER_HANDSHAKE_TRAFFIC_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      34 03 e7 81 e2 af 7b 65 08 da 28 57 4f 6e 95 a1
      ab f1 62 de 83 a9 79 27 c3 76 72 a4 a0 ce f8 a1
    HEX

    CLIENT_APPLICATION_TRAFFIC_SECRET_0 = [<<~HEX.delete(" \n")].pack("H*").freeze
      75 ec f4 b9 72 52 5a a0 dc d0 57 c9 94 4d 4c d5
      d8 26 71 d8 84 31 41 d7 dc 2a 4f f1 5a 21 dc 51
    HEX

    SERVER_APPLICATION_TRAFFIC_SECRET_0 = [<<~HEX.delete(" \n")].pack("H*").freeze
      5c 74 f8 7d f0 42 25 db 0f 82 09 c9 de 64 29 e4
      94 35 fd ef a7 ca d6 18 64 87 4d 12 f3 1c fc 8d
    HEX

    CLIENT_FINISHED = [<<~HEX.delete(" \n")].pack("H*").freeze
      14 00 00 20 23 f5 2f db 07 09 a5 5b d7 f7 9b 99
      1f 25 48 40 87 bc fd 4d 43 80 b1 23 26 a5 2a 28
      b2 e3 68 e1
    HEX
  end

  # RFC 8448 §6, Client Authentication. The server's certificate is ECDSA
  # P-256 and the client's RSA; neither private key is published.
  module ClientAuthentication
    CLIENT_X25519_PRIVATE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      c0 40 b2 bb 8f 3a dd d2 0f d4 05 8c 54 70 03 a3
      c6 f9 c1 cd 91 5d 5e 53 5c 87 d8 d1 91 aa f0 71
    HEX

    CLIENT_HELLO = [<<~HEX.delete(" \n")].pack("H*").freeze
      01 00 00 bc 03 03 6a 47 22 36 32 8b 83 af 40 38
      6d 3a 3e 1f 1c e6 24 fa 4e d8 9a b8 65 a4 ff 0f
      41 44 ce 3a e2 33 00 00 06 13 01 13 03 13 02 01
      00 00 8d 00 00 00 0b 00 09 00 00 06 73 65 72 76
      65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00
      17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00
      33 00 26 00 24 00 1d 00 20 08 9c c2 67 1f 73 8d
      9a 67 1e 5b 2e 46 49 81 d0 5b 76 e3 61 aa 22 ae
      a9 1f 1d 49 ca 10 a7 a3 62 00 2b 00 03 02 03 04
      00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04
      08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02
      06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01
    HEX

    SERVER_X25519_PRIVATE_KEY = [<<~HEX.delete(" \n")].pack("H*").freeze
      73 82 a5 ad 1c dd 20 56 ae 18 cc 70 8b d0 07 d9
      81 30 db e2 cd 4d 9e ad 9b 96 95 2b ec bb 08 88
    HEX

    SERVER_HELLO = [<<~HEX.delete(" \n")].pack("H*").freeze
      02 00 00 56 03 03 3b 50 fd f1 c3 d5 72 e4 0e 68
      95 3e 7f ff 4e 27 58 45 9c 59 af a0 58 2c 0e a0
      32 87 42 55 fe 6e 00 13 01 00 00 2e 00 33 00 24
      00 1d 00 20 6c 2e 50 e8 65 91 9a 6b 5a 12 df af
      91 8f 92 b4 42 56 7b 0f 89 bc 54 47 8c 69 21 36
      66 58 f0 62 00 2b 00 02 03 04
    HEX

    CLIENT_HANDSHAKE_TRAFFIC_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      ce c7 a3 0c 68 72 07 0f 22 a7 ee b0 65 76 8d b6
      7c 45 e2 95 33 db 87 99 08 ce 6d c6 6f 59 11 de
    HEX

    SERVER_HANDSHAKE_TRAFFIC_SECRET = [<<~HEX.delete(" \n")].pack("H*").freeze
      8b 02 d3 c0 04 42 a2 72 2c 40 98 eb e8 67 5b 23
      e8 01 51 0f 0d 7e d7 78 d8 eb 0b 8f 42 a1 9a 5e
    HEX

    ENCRYPTED_EXTENSIONS = [<<~HEX.delete(" \n")].pack("H*").freeze
      08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17
      00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
      00 02 40 01 00 00 00 00
    HEX

    CERTIFICATE_REQUEST = [<<~HEX.delete(" \n")].pack("H*").freeze
      0d 00 00 27 00 00 24 00 0d 00 20 00 1e 04 03 05
      03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06
      01 02 01 04 02 05 02 06 02 02 02
    HEX

    SERVER_CERTIFICATE = [<<~HEX.delete(" \n")].pack("H*").freeze
      0b 00 01 3b 00 00 01 37 00 01 32 30 82 01 2e 30
      81 d5 a0 03 02 01 02 02 01 07 30 0a 06 08 2a 86
      48 ce 3d 04 03 02 30 13 31 11 30 0f 06 03 55 04
      03 13 08 65 63 64 73 61 32 35 36 30 1e 17 0d 31
      36 30 37 33 30 30 31 32 34 30 30 5a 17 0d 32 36
      30 37 33 30 30 31 32 34 30 30 5a 30 13 31 11 30
      0f 06 03 55 04 03 13 08 65 63 64 73 61 32 35 36
      30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a
      86 48 ce 3d 03 01 07 03 42 00 04 08 d5 30 16 15
      75 f4 cf e7 f1 54 ee 34 48 18 00 86 00 1e 88 43
      1a 79 ee 62 ee 6e 2f 83 ef 38 ba 61 e9 fb 37 f3
      4e 00 7a 7d f4 d2 f5 b5 6d 1f 04 ec e4 5d 62 1f
      46 84 06 f5 c3 a1 51 58 94 8d d0 a3 1a 30 18 30
      09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55 1d
      0f 04 04 03 02 07 80 30 0a 06 08 2a 86 48 ce 3d
      04 03 02 03 48 00 30 45 02 21 00 df 30 fd 45 07
      f5 ed d2 2c 1a 6f f8 6d b4 79 ca 69 3f ee ca 3b
      71 b3 f9 ef 55 6b 29 37 c0 59 4d 02 20 62 e2 a4
      72 50 d3 20 fe a8 3c 7e 2d cb 5b 76 a5 0e 02 00
      c0 9a db d1 3f ee 94 6e 51 3e 01 1d 11 00 00
    HEX

    SERVER_CERTIFICATE_VERIFY = [<<~HEX.delete(" \n")].pack("H*").freeze
      0f 00 00 4b 04 03 00 47 30 45 02 21 00 d7 a4 d3
      4b d5 4f 55 fe e1 a8 96 25 67 8c 3d d5 e5 f6 0d
      ac 73 ec 94 0c 5c 7b 93 04 a0 20 84 a9 02 20 28
      9f 59 5e d4 88 b9 ac 68 9a 3d 19 2b 1a 8b b3 8f
      34 af 78 74 c0 59 c9 80 6a 1f 38 26 93 53 e8
    HEX

    SERVER_FINISHED = [<<~HEX.delete(" \n")].pack("H*").freeze
      14 00 00 20 93 b7 0c df 47 81 98 5b 96 34 5c aa
      c7 01 b4 e7 50 d3 04 2d f1 a6 89 d8 fa ca 81 22
      51 11 3c 11
    HEX

    CLIENT_APPLICATION_TRAFFIC_SECRET_0 = [<<~HEX.delete(" \n")].pack("H*").freeze
      73 c2 e8 90 fa 8d 06 72 58 d6 d5 0f a9 2f e4 56
      b0 98 cf 00 d9 72 7e ed 91 e8 89 2e f4 e6 f8 60
    HEX

    SERVER_APPLICATION_TRAFFIC_SECRET_0 = [<<~HEX.delete(" \n")].pack("H*").freeze
      c4 9a 91 fa f5 7f 8c 54 5d 50 48 a0 15 bf 84 9f
      f6 39 42 e4 a7 ed cd 31 9f 8b 43 8a 97 c5 2e 21
    HEX

    CLIENT_CERTIFICATE = [<<~HEX.delete(" \n")].pack("H*").freeze
      0b 00 01 bf 00 00 01 bb 00 01 b6 30 82 01 b2 30
      82 01 1b a0 03 02 01 02 02 01 01 30 0d 06 09 2a
      86 48 86 f7 0d 01 01 0b 05 00 30 11 31 0f 30 0d
      06 03 55 04 03 13 06 63 6c 69 65 6e 74 30 1e 17
      0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17 0d
      32 36 30 37 33 30 30 31 32 33 35 39 5a 30 11 31
      0f 30 0d 06 03 55 04 03 13 06 63 6c 69 65 6e 74
      30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01
      05 00 03 81 8d 00 30 81 89 02 81 81 00 c3 81 75
      e0 04 a6 8d 09 3f 82 3b 9c 37 9d 20 1f bc 0b b7
      a1 c7 91 90 5e 3f bf 76 84 7e 44 e7 51 eb bc d3
      60 bd 94 5c 81 e5 22 2b cc 88 46 d3 a8 a0 f9 3e
      9b f5 be ba bd 92 ed f1 de 1f f1 90 21 70 3e 7a
      b6 c0 90 15 13 f9 7e 39 b1 11 f0 9c 93 48 97 1c
      7b 21 19 84 a7 54 cd 45 fe 09 5a f0 ea 42 36 82
      9b cc f7 a7 fe 9b 28 88 e7 8a b4 77 69 0a 5b 9e
      1c cb e9 1c 6a 4a 0f 97 a7 e0 28 42 01 02 03 01
      00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30
      00 30 0b 06 03 55 1d 0f 04 04 03 02 07 80 30 0d
      06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 81 81
      00 1a 7a 5a 01 85 32 b0 22 af 07 67 d4 86 16 0c
      ff 2d 16 7a 19 15 d2 38 35 b5 45 94 91 6d c6 80
      be 5d 2e 62 60 76 c5 d5 27 22 eb cc 77 5d 7d 99
      f9 80 be 2f c9 4d 34 ac f6 cc 00 ba 90 cb cf b0
      60 8a a1 e7 e3 97 1e f0 c0 7a 41 d4 7a d8 34 5d
      1f 81 fe 41 8a 1c f4 10 54 42 9f d2 17 bd 77 7d
      c1 cf 08 f0 5d f9 07 99 c6 59 36 1e 0f 1a 8e e4
      ac 0f 78 97 42 0b db c8 23 da 80 a2 f2 ba 23 08
      1c 00 00
    HEX

    CLIENT_CERTIFICATE_VERIFY = [<<~HEX.delete(" \n")].pack("H*").freeze
      0f 00 00 84 08 04 00 80 18 6b 22 23 b5 03 a7 59
      c3 5d ba 0e 97 21 b4 b5 79 13 8d 5f 0f 5e 6e c7
      fe aa f2 7f 3a d7 f3 86 c2 c7 bd 7c b2 be 52 fb
      f5 ed 83 93 f4 06 ee 79 36 96 92 ec 7a c6 95 65
      1d 85 82 19 e6 72 a8 eb 7b 2a 67 7b 64 0b 46 ab
      63 0e dc 5f 3f 2f 82 72 b9 c0 d9 06 f8 1f 84 dd
      c5 b8 c7 bc f9 55 c7 8a 3c f9 9e 50 16 f7 3e 04
      eb 7d fc b2 88 33 f1 3e 8f 75 ec 2f f3 58 1e 2f
      09 8a d4 15 7f d6 d6 ad
    HEX

    CLIENT_FINISHED = [<<~HEX.delete(" \n")].pack("H*").freeze
      14 00 00 20 9a fe 2b a2 f6 3a 09 d2 29 d8 a4 29
      e5 b3 7f fd 9f cc 73 bd b5 91 1b 82 42 59 72 aa
      28 92 44 0f
    HEX
  end
end
