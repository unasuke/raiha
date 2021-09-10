require 'bundler/inline'

gemfile do
  source "https://rubygems.org"
  gem "bindata"
end

require 'openssl'
require 'bindata'

def tms(bit)
  case bit
  when 0 then 6
  when 1 then 14
  when 2 then 30
  when 3 then 62
  end
end

class QUICInitialPacket < BinData::Record
  endian :big
  bit1 :header_form, asserted_value: 1
  bit1 :fixed_bit, asserted_value: 1
  bit2 :long_packet_type, asserted_value: 0
  bit2 :reserved_bit
  bit2 :packet_number_length
  bit32 :version
  bit8 :destination_connection_id_length
  bit :destination_connection_id, nbits: lambda { destination_connection_id_length * 8 }
  bit8 :source_connection_id_length
  bit :source_connection_id, nbits: lambda { source_connection_id_length * 8 }
  bit2 :token_two_most_significant_bits
  bit :token_length, nbits: lambda { tms(token_two_most_significant_bits) }
  string :token, read_length: lambda { token_length }
  bit2 :length_two_most_significant_bits
  bit :length_length, nbits: lambda { tms(length_two_most_significant_bits) }
  bit :packet_number, nbits: lambda { (packet_number_length + 1) * 8 }
  string :payload, read_length: lambda { length_length - (packet_number_length + 1) }
end

class QUICProtectedInitialPacket < BinData::Record
  endian :big
  bit1 :header_form, asserted_value: 1
  bit1 :fixed_bit, asserted_value: 1
  bit2 :long_packet_type, asserted_value: 0
  bit2 :reserved_bit
  bit2 :packet_number_length # unuse (protected value)
  bit32 :version
  bit8 :destination_connection_id_length
  bit :destination_connection_id, nbits: lambda { destination_connection_id_length * 8 }
  bit8 :source_connection_id_length
  bit :source_connection_id, nbits: lambda { source_connection_id_length * 8 }
  # Variable-Length Integer Encoding for token
  bit2 :token_two_most_significant_bits
  bit :token_length, nbits: lambda { tms(token_two_most_significant_bits) }
  string :token, read_length: lambda { token_length }
  # Variable-Length Integer Encoding for length
  bit2 :length_two_most_significant_bits
  bit :length_length, nbits: lambda { tms(length_two_most_significant_bits) }
  string :payload, read_length: lambda { length_length - (packet_number_length + 1) }
end

class QUICCRYPOFrame < BinData::Record
  endian :big
  bit8 :frame_type, asserted_value: 0x06
  bit2 :offset_two_most_significat_bits
  bit :offset, nbits: lambda { tms(offset_two_most_significat_bits) }
  bit2 :length_two_most_significant_bits
  bit :length_length, nbits: lambda { tms(length_two_most_significant_bits) }
  string :data, read_length: lambda { length_length }
end

raw_packet = [
  "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11" +
  "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" +
  "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" +
  "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" +
  "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" +
  "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" +
  "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" +
  "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" +
  "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" +
  "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" +
  "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" +
  "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" +
  "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" +
  "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" +
  "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" +
  "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" +
  "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" +
  "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" +
  "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" +
  "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" +
  "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" +
  "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" +
  "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" +
  "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" +
  "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" +
  "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" +
  "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" +
  "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" +
  "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" +
  "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" +
  "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" +
  "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" +
  "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" +
  "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" +
  "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" +
  "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" +
  "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" +
  "e221af44860018ab0856972e194cd934"
].pack("H*")

# socket = UDPSocket.new
# socket.bind("0.0.0.0", 8080)

# begin
#   raw_packet = socket.recvfrom_nonblock(2000)[0]
# rescue IO::WaitReadable
#   retry
# end

# raw_packet = [
# "c80000000110b61d55525ce5050363d471738ff245271476637acd05d5240a911e5d41bc8286de" +
# "d2a9434c00412051757149e6b130d9c5a4670be3ca36bfe8506a4f749b51b8532743121fbd7b6e6" +
# "7b103551297773869b0d9037203fb2d7840a865bd0fbf0da65f68223842a0a73c4882e1906bcfc4" +
# "31d116a10d7ea0a06106d91577b766af166708c142db8df5d5b32ba6750ef1e3d2a083c7a6c97d0" +
# "06540f0cf1e61ed8fbaa8658ce2a5425b3b1dca2ef3c03152194f89a599402cacc77cef2771bf39" +
# "57691c7db4b1b3cdf8c08c79737be456558d1d1b759e44a7fa81b0f96d2dc4fb4cb165579dc3a1e" +
# "375cafda21b4965f072c66b8b94f8db395f957463ebe6d79690954cd4806e773d79ccfe60c78d7b" +
# "3dda9512c299bc0f7809006f42ca39e7758e903966543c77e5a2db90d7954ea54472ab3ed3c454b" +
# "f61f6a3c8f6dc5fde4e8d00bba53f43956b32000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000000000000000000000000000000000000000000000000000" +
# "0000000000000000000000000000000"
# ].pack("H*")
# pp raw_packet

packet = QUICProtectedInitialPacket.read(raw_packet)
# pp packet

pp packet.destination_connection_id_length
pp packet.source_connection_id_length
pp (tms(packet.length_two_most_significant_bits) + 2) / 8
pp (tms(packet.token_two_most_significant_bits) + 2) / 8
pp packet.token_length
# ここからheaderの保護を解除するためのコード
pn_offset = 7 + 
  packet.destination_connection_id_length +
  packet.source_connection_id_length +
  (tms(packet.length_two_most_significant_bits) + 2) / 8 +
  (tms(packet.token_two_most_significant_bits) + 2) / 8 +
  packet.token_length
sample_offset = pn_offset + 4
# pp pn_offset
pp "pn_offset #{pn_offset}"
    pp "sample_offset #{sample_offset}"

sample = raw_packet[sample_offset...sample_offset+16]
pp "sample #{sample.unpack1("H*")}"

enc = OpenSSL::Cipher.new('aes-128-ecb')
enc.encrypt

enc.key = ["9f50449e04a0e810283a1e9933adedd2"].pack("H*") # hp

mask = ""
mask << enc.update(sample)
mask << enc.final

pp mask.unpack1("H*")

# https://www.rfc-editor.org/rfc/rfc9001#name-header-protection-applicati
# headerを保護するときとは逆の手順を踏んで保護を解除する
raw_packet[0] = [(raw_packet[0].unpack1('H*').to_i(16) ^ (mask[0].unpack1('H*').to_i(16) & 0x0f)).to_s(16)].pack("H*")

# https://www.rfc-editor.org/rfc/rfc9001#figure-6
pn_length = (raw_packet[0].unpack1('H*').to_i(16) & 0x03) + 1

packet_number =
  (raw_packet[pn_offset...pn_offset+pn_length].unpack1("H*").to_i(16) ^ mask[1...1+pn_length].unpack1("H*").to_i(16)).to_s(16)

# 先頭の0が消えてしまうので、パケット番号の長さに満たないぶんを zero fillする
raw_packet[pn_offset...pn_offset+pn_length] = [("0" * (pn_length * 2 - packet_number.length)) + packet_number].pack("H*")

# headerの保護が外れたpacket (payloadはまだ暗号)
packet = QUICInitialPacket.read(raw_packet)


# 復号のためheaderのみを取り出す
header_length = raw_packet.length - packet.payload.length


# payloadの復号
dec = OpenSSL::Cipher.new('aes-128-gcm')
dec.decrypt
dec.key = ["1f369613dd76d5467730efcbe3b1a22d"].pack("H*") # quic key
dec.iv = [("fa044b2f42a3fd3b46fb255c".to_i(16) ^ packet.packet_number).to_s(16)].pack("H*") # quic iv
pp  raw_packet[0...(raw_packet.length - packet.payload.length)].unpack1("H*")
dec.auth_data = raw_packet[0...(raw_packet.length - packet.payload.length)]
pp packet.payload[packet.payload.length-16...packet.payload.length].unpack1("H*")
dec.auth_tag = packet.payload[packet.payload.length-16...packet.payload.length]

payload = ""
payload << dec.update(packet.payload[0...packet.payload.length-16])
payload << dec.final

# 復号したpayloadをCRYPTO frameとしてparse
# pp QUICCRYPOFrame.read(payload)
# => {:frame_type=>6,
# :offset_two_most_significat_bits=>0,
# :offset=>0,
# :length_two_most_significant_bits=>1,
# :length_length=>241,
# :data=>
#  "\x01\x00\x00\xED\x03\x03\xEB\xF8\xFAV\xF1)9\xB9XJ8\x96G.\xC4\v\xB8c\xCF\xD3\xE8h\x04\xFE:G\xF0j+iHL\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\xC0" +
#  "\x00\x00\x00\x10\x00\x0E\x00\x00\vexample.com\xFF\x01\x00\x01\x00\x00\n" +
#  "\x00\b\x00\x06\x00\x1D\x00\x17\x00\x18\x00\x10\x00\a\x00\x05\x04alpn\x00\x05\x00\x05\x01\x00\x00\x00\x00\x003\x00&\x00$\x00\x1D\x00 \x93p\xB2\xC9\xCA\xA4" +
#  "\x7F\xBA\xBA\xF4U\x9F\xED\xBAu=\xE1q\xFAq\xF5\x0F\x1C\xE1]C\xE9\x94\xECt\xD7H\x00+\x00\x03\x02\x03\x04\x00\r\x00\x10\x00\x0E\x04\x03\x05\x03\x06\x03\x02\x03" +
#  "\b\x04\b\x05\b\x06\x00-\x00\x02\x01\x01\x00\x1C\x00\x02@\x01\x009\x002\x04\b\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x05\x04\x80\x00\xFF\xFF\a\x04\x80\x00\xFF\xFF\b" +
#  "\x01\x10\x01\x04\x80\x00u0\t\x01\x10\x0F\b\x83\x94\xC8\xF0>QW\b\x06\x04\x80\x00\xFF\xFF"
# }
