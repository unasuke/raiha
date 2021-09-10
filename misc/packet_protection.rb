require 'openssl'


payload = 
  "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" +
  "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578" +
  "616d706c652e636f6dff01000100000a00080006001d00170018001000070005" +
  "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" +
  "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" +
  "0d0010000e0403050306030203080408050806002d00020101001c0002400100" +
  "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" +
  "75300901100f088394c8f03e51570806048000ffff" +
  ("00" * 917)

encryptor = OpenSSL::Cipher.new("AES-128-GCM")
encryptor.encrypt
# encryptor.key = ["cf3a5331653c364c88f0f379b6067e37"].pack("H*")
encryptor.key =   ["1f369613dd76d5467730efcbe3b1a22d"].pack("H*")
nonce = ("fa044b2f42a3fd3b46fb255c".to_i(16) ^ 2).to_s(16)
# encryptor.iv = ["0ac1493ca1905853b0bba03e"].pack("H*")
# encryptor.iv = ["fa044b2f42a3fd3b46fb255c"].pack("H*")
encryptor.iv = [nonce].pack("H*")
encryptor.auth_data = ["c300000001088394c8f03e5157080000449e00000002"].pack("H*")

protected_payload = ""
protected_payload << encryptor.update([payload].pack("H*"))
protected_payload << encryptor.final

# pp protected_payload.unpack1("H*")
# pp encryptor.auth_tag.unpack1("H*")

# pp ["0ac1493ca1905853b0bba03e"].pack("H*").to_i(2)
# pp encryptor.auth_tag
# pp payload.size
protected_payload << encryptor.auth_tag

pp protected_payload.unpack1("H*")

pp payload
