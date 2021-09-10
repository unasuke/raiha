require 'openssl'
require 'bindata'

class QUICInitialPacket < BinData::Record
  # ....
end

class QUICProtectedInitialPacket < BinData::Record
  # ....
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
  # .......
].pack("H*")

packet = QUICProtectedInitialPacket.read(raw_packet)

# ここからheaderの保護を解除するためのコード
pn_offset = 7 + 
  packet.destination_connection_id_length +
  packet.source_connection_id_length +
  (tms(packet.length_two_most_significant_bits) + 2) / 8 +
  (tms(packet.token_two_most_significant_bits) + 2) / 8 +
  packet.token_length

sample_offset = pn_offset + 4

sample = raw_packet[sample_offset...sample_offset+16]

enc = OpenSSL::Cipher.new('aes-128-ecb')
enc.encrypt

enc.key = ["9f50449e04a0e810283a1e9933adedd2"].pack("H*") # hp
mask = ""
mask << enc.update(sample)
mask << enc.final

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
dec.auth_data = raw_packet[0...(raw_packet.length - packet.payload.length)]
dec.auth_tag = packet.payload[packet.payload.length-16...packet.payload.length]

payload = ""
payload << dec.update(packet.payload[0...packet.payload.length-16])
payload << dec.final

# 復号したpayloadをCRYPTO frameとしてparse
pp QUICCRYPOFrame.read(payload)
# => {:frame_type=>6,
# :offset_two_most_significat_bits=>0,
# :offset=>0,
# :length_two_most_significant_bits=>1,
# :length_length=>241,
# :data=>
#  "\x01\x00\x00\xED\x03\x03\xEB\xF8\xFAV\xF1)9\xB9XJ8\x96G.\xC4\v\xB8c\xCF\xD3\xE8h\x04\xFE:G\xF0j+iHL" +
#  "\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\xC0\x00\x00\x00\x10\x00\x0E\x00\x00\vexample.com\xFF\x01\x00\x01\x00\x00\n" +
#  "\x00\b\x00\x06\x00\x1D\x00\x17\x00\x18\x00\x10\x00\a\x00\x05\x04alpn\x00\x05\x00\x05\x01\x00\x00\x00\x00" +
#  ....
