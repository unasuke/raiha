# frozen_string_literal: true

require "test_helper"
require "raiha/quic/crypto"
require "raiha/quic/crypto/header_protection"
require "raiha/quic/crypto/aead"
require "raiha/crypto_util"

class RaihaQuicCryptoHeaderProtectionTest < Minitest::Test
  # test data from RFC 9001 Appendix A https://www.rfc-editor.org/rfc/rfc9001.html#section-appendix.a

  PADDING = "\x00" * 917

  RFC9001_APPENDIX_A_INITIAL_PACKET_PLAIN = IO::Buffer.for([
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" \
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578" \
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005" \
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" \
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" \
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100" \
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" \
    "75300901100f088394c8f03e51570806048000ffff"
  ].pack("H*") + PADDING)

  RFC9001_APPENDIX_A_INITIAL_PACKET_PLAIN_HEADER = IO::Buffer.for([
    "c300000001088394c8f03e5157080000449e00000002"
  ].pack("H*"))

  RFC9001_APPENDIX_A_INITIAL_PACKET_PROTECTED = IO::Buffer.for([
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11" \
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" \
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" \
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" \
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" \
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" \
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" \
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" \
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" \
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" \
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" \
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" \
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" \
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" \
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" \
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" \
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" \
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" \
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" \
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" \
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" \
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" \
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" \
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" \
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" \
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" \
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" \
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" \
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" \
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" \
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" \
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" \
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" \
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" \
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" \
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" \
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" \
    "e221af44860018ab0856972e194cd934"
  ].pack("H*"))

  RFC9001_APPENDIX_A_DESTINATION_CONNECTION_ID = ["8394c8f03e515708"].pack("H*")

  def test_apply
    initial_secret = OpenSSL::HMAC.digest("SHA256", Raiha::Quic::Crypto::INITIAL_SALT_VERSION_1, RFC9001_APPENDIX_A_DESTINATION_CONNECTION_ID)
    secret = Raiha::CryptoUtil.hkdf_expand_label(initial_secret, "client in", "", 32)
    quic_key = Raiha::CryptoUtil.hkdf_expand_label(secret, "quic key", "", 16)
    quic_iv = Raiha::CryptoUtil.hkdf_expand_label(secret, "quic iv", "", 12)
    quic_hp = Raiha::CryptoUtil.hkdf_expand_label(secret, "quic hp", "", 16)
    hp = Raiha::Quic::Crypto::HeaderProtection.new(cipher_name: "aes-128-ecb", key: quic_hp)
    aead = Raiha::Quic::Crypto::AEAD.new("aes-128-gcm", quic_key, quic_iv)
    encrypted_payload = aead.encrypt(RFC9001_APPENDIX_A_INITIAL_PACKET_PLAIN.get_string, RFC9001_APPENDIX_A_INITIAL_PACKET_PLAIN_HEADER.get_string, 2)
    protected_payload = hp.apply(RFC9001_APPENDIX_A_INITIAL_PACKET_PLAIN_HEADER, IO::Buffer.for(encrypted_payload))
    assert_equal RFC9001_APPENDIX_A_INITIAL_PACKET_PROTECTED, protected_payload
  end

  def test_remove
    initial_secret = OpenSSL::HMAC.digest("SHA256", Raiha::Quic::Crypto::INITIAL_SALT_VERSION_1, RFC9001_APPENDIX_A_DESTINATION_CONNECTION_ID)
    secret = Raiha::CryptoUtil.hkdf_expand_label(initial_secret, "client in", "", 32)
    quic_key = Raiha::CryptoUtil.hkdf_expand_label(secret, "quic key", "", 16)
    quic_iv = Raiha::CryptoUtil.hkdf_expand_label(secret, "quic iv", "", 12)
    quic_hp = Raiha::CryptoUtil.hkdf_expand_label(secret, "quic hp", "", 16)
    hp = Raiha::Quic::Crypto::HeaderProtection.new(cipher_name: "aes-128-ecb", key: quic_hp)
    removed = hp.remove(RFC9001_APPENDIX_A_INITIAL_PACKET_PROTECTED, 18)
    assert_equal ["c300000001088394c8f03e5157080000449e00000002"].pack("H*"), removed[:plain_header].get_string
    assert_equal 2, removed[:packet_number]
  end
end
