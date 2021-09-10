# This software is released under the MIT License.
# Copyright 2021 Yusuke Nakamura
# Copyright 2021 Nao Yonashiro
# https://opensource.org/licenses/MIT

require 'bundler/inline'
require "socket"

gemfile do
  source "https://rubygems.org"
  gem "bindata"
  gem "tttls1.3"
end

require 'tttls1.3/key_schedule'
require "openssl"

def xor_s(a, b)
    a.unpack("C*").zip(b.unpack("C*")).map{|x, y| x ^ y}.pack("C*")
end

class VarInt < BinData::Primitive
  bit2 :bytes_log2, :value => lambda { (val.bit_length + 1) / 8 }
  bit :val, :nbits => lambda { bytes * 8 - 2 }
  
  def get
    self.val
  end
  
  def set(v)
    self.val = v
  end
  
  def bytes
    2 ** self.bytes_log2
  end
end
  
class QUICInitialPacket < BinData::Record
  endian :big
  hide :reserved_bits, :fixed_bit, :data
  bit1 :header_form, asserted_value: 1
  bit1 :fixed_bit, asserted_value: 1
  bit2 :long_packet_type, asserted_value: 0
  bit2 :reserved_bits        # protected
  bit2 :packet_number_length # protected
  bit32 :version
  bit8 :destination_connection_id_length, :value => lambda { destination_connection_id.length }
  string :destination_connection_id, :read_length => :destination_connection_id_length
  bit8 :source_connection_id_length, :value => lambda { source_connection_id.length }
  string :source_connection_id, :read_length => :source_connection_id_length
  var_int :token_length
  string :token, :read_length => :token_length
  var_int :len
  string :data, :read_length => :len # protected

  def header_byte_length
    (1 + # header_form
    1 + # fixed_bit
    2 + # long_packet_type
    2 + # packet_number_length
    2 + # reserved_bits
    32 + # version
    8 + # destination_connection_id_length
    8  # source_connection_id_length
    ) / 8 + 
    self.destination_connection_id_length +
    self.source_connection_id_length +
    self.token_length.bytes +
    self.token_length +
    self.len.bytes
  end

  def remove_protection!()
    initial_salt = ['38762cf7f55934b34d179ae6a4c80cadccbb7f0a'].pack('H*')
    initial_secret = OpenSSL::HMAC.digest('SHA256', initial_salt, self.destination_connection_id)
    client_initial_secret = TTTLS13::KeySchedule.hkdf_expand_label(initial_secret, 'client in', '', 32, 'SHA256')
    key = TTTLS13::KeySchedule::hkdf_expand_label(client_initial_secret, 'quic key', '', 16, 'SHA256')
    iv = TTTLS13::KeySchedule::hkdf_expand_label(client_initial_secret, 'quic iv', '', 12, 'SHA256')
    hp = TTTLS13::KeySchedule::hkdf_expand_label(client_initial_secret, 'quic hp', '', 16, 'SHA256')

    pn_offset = 7 +
      self.destination_connection_id_length +
      self.source_connection_id_length +
      self.len.bytes +
      self.token_length.bytes +
      self.token_length
    sample_offset = pn_offset + 4
    data_offset = sample_offset - header_byte_length
    enc = OpenSSL::Cipher.new('aes-128-ecb')
    enc.encrypt
    enc.key = hp
    mask = ""
    mask << enc.update(self.data[data_offset...data_offset+16])
    mask << enc.final

    # long header: 0x0f, short header: 0x1f
    m = mask.unpack1("C") & 0x0f
    self.reserved_bits ^= (m >> 2) & 0x03
    self.packet_number_length ^= m & 0x03

    pn_length = self.packet_number_length + 1
    pn = xor_s(self.data[...pn_length], mask[1...1+pn_length])
    tmp = self.data[0...]
    tmp[...pn_length] = pn
    self.data = tmp

    dec = OpenSSL::Cipher.new('aes-128-gcm')
    dec.decrypt
    dec.key = key
    dec.iv = [(iv.unpack1("H*").to_i(16) ^ self.packet_number.unpack1("H*").to_i(16)).to_s(16)].pack("H*")
    dec.auth_data = self.to_binary_s[...-self.payload.length]
    dec.auth_tag = self.payload[-16...]
    decoded_payload = ""
    decoded_payload << dec.update(self.payload[...-16])
    decoded_payload << dec.final

    tmp = self.data[0...]
    tmp[pn_length...] = decoded_payload
    self.data = tmp
  end

  def packet_number
    self.data[...self.packet_number_length+1]
  end

  def payload
    self.data[self.packet_number_length+1...]
  end
end

class QUICCRYPTOFrame < BinData::Record
  endian :big
  bit8 :frame_type, asserted_value: 0x06
  var_int :offset
  var_int :len
  string :data, :read_length => :len
end

class TLSHandshakeClientHello < BinData::Record
  endian :big
  bit8 :message_type
  uint24 :message_length
  uint16 :protocol_version
  string :random, read_length: 4
end

socket = UDPSocket.new
socket.bind("0.0.0.0", 8080)

begin
    raw_packet = socket.recvfrom_nonblock(2000)[0]
rescue IO::WaitReadable
    retry
end

pp initial_packet = QUICInitialPacket.read(raw_packet)
initial_packet.remove_protection!
pp initial_packet
frame=QUICCRYPTOFrame.read(initial_packet.payload)

pp TLSHandshakeClientHello.read(frame.data)
