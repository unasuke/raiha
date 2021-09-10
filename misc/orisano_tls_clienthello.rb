# This software is released under the MIT License.
# Copyright 2021 Yusuke Nakamura
# Copyright 2021 Nao Yonashiro
# https://opensource.org/licenses/MIT

require "bundler/inline"
require "socket"

gemfile do
  source "https://rubygems.org"
  gem "bindata"
  gem "tttls1.3"
  gem 'pry'
end

require "tttls1.3/key_schedule"
require "openssl"

def xor_s(a, b)
  a.unpack("C*").zip(b.unpack("C*")).map{|x, y| x ^ y}.pack("C*")
end

class VarInt < BinData::Primitive
  bit2 :bytes_log2
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

class QuicLongHeader < BinData::Record
  hide   :header_form, :fixed_bit

  bit1   :header_form, :asserted_value => 1
  bit1   :fixed_bit, :asserted_value => 1
  bit2   :long_packet_type
  bit4   :type_specific_bits
  bit32  :version

  bit8   :destination_connection_id_length
  string :destination_connection_id, :length => :destination_connection_id_length
  bit8   :source_connection_id_length
  string :source_connection_id, :length => :source_connection_id_length

  def bytes
    1 + 4 + 1 + destination_connection_id.length + 1 + source_connection_id.length
  end
end

class QuicKeys
  def initialize(data)
    initial_salt = ["38762cf7f55934b34d179ae6a4c80cadccbb7f0a"].pack("H*")
    initial_secret = OpenSSL::HMAC.digest("SHA256", initial_salt, data)
    @client_initial_secret = TTTLS13::KeySchedule.hkdf_expand_label(initial_secret, "client in", "", 32, "SHA256")
  end

  def hp
    TTTLS13::KeySchedule::hkdf_expand_label(@client_initial_secret, "quic hp", "", 16, "SHA256")
  end

  def iv
    TTTLS13::KeySchedule::hkdf_expand_label(@client_initial_secret, "quic iv", "", 12, "SHA256")
  end

  def key
    TTTLS13::KeySchedule::hkdf_expand_label(@client_initial_secret, "quic key", "", 16, "SHA256")
  end
end

class QuicInitialPacketHeader < BinData::Record
  default_parameter :unprotected => false

  quic_long_header :long_header

  var_int :token_length
  string  :token, :length => :token_length
  var_int :len
  string  :packet_number, :read_length => :packet_number_length

  virtual :unprotected, :inital_value => :unprotected

  def remove_protection(raw_packet)
    pn_offset = long_header.bytes + token_length.bytes + token.length + len.bytes
    sample_offset = pn_offset + 4

    sample = raw_packet[sample_offset...sample_offset+16]

    keys = QuicKeys.new(long_header.destination_connection_id)

    enc = OpenSSL::Cipher.new("aes-128-ecb").encrypt
    enc.key = keys.hp
    mask = enc.update(sample) + enc.final

    raw_packet[0] = [raw_packet.unpack1("C") ^ (mask.unpack1("C") & 0x0f)].pack("C")
    pn_length = (raw_packet.unpack1("C") & 0x03) + 1
    raw_packet[pn_offset...pn_offset+pn_length] = xor_s(raw_packet[pn_offset...pn_offset+pn_length], mask[1...1+pn_length])
  end

  def packet_number_length
    if unprotected
      (long_header.type_specific_bits & 0x03) + 1
    else
      0
    end
  end
end

class QuicInitialPacket < BinData::Record
  quic_initial_packet_header :header, :unprotected => true
  string :payload, :read_length => lambda { header.len - header.packet_number_length }

  def decrypt!
    keys = QuicKeys.new(header.long_header.destination_connection_id)

    dec = OpenSSL::Cipher.new("aes-128-gcm").decrypt
    dec.key = keys.key
    dec.iv = xor_s(keys.iv, header.packet_number.rjust(12, "\x00"))
    dec.auth_data = header.to_binary_s
    dec.auth_tag = self.payload[-16...]
    self.payload = dec.update(self.payload[...-16]) + dec.final
  end
end

class QuicPaddingFrame < BinData::Record
end

class QuicPingFrame < BinData::Record
end

class QuicCryptoFrame < BinData::Record
  var_int :offset
  var_int :len
  string  :data, :read_length => :len
end

class QuicFrame < BinData::Record
  bit8   :frame_type
  choice :body, :selection => :frame_type do
    quic_padding_frame 0x00
    quic_ping_frame    0x01
    quic_crypto_frame  0x06
  end
end

class QuicFrames < BinData::Record
  array :frames, :type => :quic_frame, :read_until => :eof
end

class TlsProtocolVersion < BinData::Record
  bit8 :major
  bit8 :minor
end

class TlsRandom < BinData::Record
  bit32 :gmt_unix_time
  string :random_bytes, :length => 28
end

class TlsServerNameExtension < BinData::Record
  bit16 :len
  buffer :server_name_list, :length => :len do
    array :read_until => :eof do
      bit8   :name_type, :asserted_value => 0
      bit16  :name_length
      string :name, :read_length => :name_length
    end
  end

  def pretty
    { list: server_name_list.map { |s| s['name'] } }
  end
end

class TlsSupportedGroupsExtension < BinData::Record
  bit16 :len
  buffer :named_group_list, :length => :len do
    array :type => :bit16, :read_until => :eof
  end

  def group_name(type)
    case type
    when 0x0017 then 'secp256r1'
    when 0x0018 then 'secp384r1'
    when 0x0019 then 'secp521r1'
    when 0x001d then 'x25519'
    when 0x001e then 'x448'
    when 0x0100 then 'ffdhe2048'
    when 0x0101 then 'ffdhe3072'
    when 0x0102 then 'ffdhe4096'
    when 0x0103 then 'ffdhe6144'
    when 0x0104 then 'ffdhe8192'
    when 0x01fc..0x01ff then 'ffdhe_private_use'
    when 0xfe00..0xfeff then 'ecdhe_private_use'
    end
  end

  def pretty
    { list: named_group_list.map { |g| group_name(g) } }
  end
end

class TlsApplicationLayerProtocolNegotiationExtension < BinData::Record
  bit16 :len
  buffer :protocol_name_list, :length => :len do
    array :read_until => :eof do
      bit8 :len
      string :name, :length => :len
    end
  end

  def pretty
    { protocol_name_list: protocol_name_list.map { |l| l['name'] } }
  end
end

class TlsSignatureAlgorithmsExtension < BinData::Record
  bit16 :len
  buffer :supported_signature_algorithms, :length => :len do
    array :type => :bit16, :read_until => :eof
  end

  def algorithm_name(id)
    case id
    when 0x0401 then 'rsa_pkcs1_sha256'
    when 0x0501 then 'rsa_pkcs1_sha384'
    when 0x0601 then 'rsa_pkcs1_sha512'
    when 0x0403 then 'ecdsa_secp256r1_sha256'
    when 0x0503 then 'ecdsa_secp384r1_sha384'
    when 0x0603 then 'ecdsa_secp521r1_sha512'
    when 0x0804 then 'rsa_pass_rsae_sha256'
    when 0x0805 then 'rsa_pass_rsae_sha384'
    when 0x0806 then 'rsa_pass_rsae_sha512'
    when 0x0807 then 'ed25519'
    when 0x0808 then 'ed448'
    when 0x0809 then 'rsa_pss_pss_sha256'
    when 0x080a then 'rsa_pss_pss_sha384'
    when 0x080b then 'rsa_pss_pss_sha512'
    when 0x0201 then 'rsa_pksc1_sha1' # legacy
    when 0x0203 then 'ecdsa_sha1' # legacy
    when 0xfe00..0xffff then 'private_use'
    end
  end

  def pretty
    { signature_algorithms: supported_signature_algorithms.map { |a| algorithm_name(a) }}
  end
end

class TlsKeyShareExtension < BinData::Record
  bit16 :len
  buffer :client_shares, :length => :len do
    array :read_until => :eof do
      bit16 :group
      bit16 :key_exchange_length
      string :key_exchange, :length => :key_exchange_length
    end
  end

  def group_name(type)
    case type
    when 0x0017 then 'secp256r1'
    when 0x0018 then 'secp384r1'
    when 0x0019 then 'secp521r1'
    when 0x001d then 'x25519'
    when 0x001e then 'x448'
    when 0x0100 then 'ffdhe2048'
    when 0x0101 then 'ffdhe3072'
    when 0x0102 then 'ffdhe4096'
    when 0x0103 then 'ffdhe6144'
    when 0x0104 then 'ffdhe8192'
    when 0x01fc..0x01ff then 'ffdhe_private_use'
    when 0xfe00..0xfeff then 'ecdhe_private_use'
    end
  end

  def pretty
    { client_shares: client_shares.map { |c| { group: group_name(c["group"]), key_exchange_length: c["key_exchange_length"], key_exchange: c["key_exchange"] } } }
  end
end

class TlsPskKeyExchangeModesExtension < BinData::Record
  bit8 :len
  array :ke_modes, :type => :bit8, :initial_length => :len

  def key_exchange_mode_name(ke)
    case ke
    when 0x0 then 'psk_ke'
    when 0x1 then 'psk_dhe_ke'
    end
  end

  def pretty
    { ke_modes: ke_modes.map { |ke| key_exchange_mode_name(ke) } }
  end
end

class TlsSupportedVersionsExtension < BinData::Record
  bit8 :len
  buffer :versions, :length => :len do
    array :type => :tls_protocol_version, :read_until => :eof
  end

  def pretty
    self
  end
end

class QuicTransportParametersExtension < BinData::Record
  endian :big
  array :params, :read_until => :eof do
    hide :len
    var_int :id
    var_int :len
    string :val, :read_length => :len
  end

  def param_name(val)
    case val
    when 0x00 then 'original_destination_connection_id'
    when 0x01 then 'max_idle_timeout'
    when 0x02 then 'stateless_reset_token'
    when 0x03 then 'max_udp_payload_size'
    when 0x04 then 'initial_max_data'
    when 0x05 then 'inital_max_stream_data_bidi_local'
    when 0x06 then 'initial_max_stream_data_bidi_remote'
    when 0x07 then 'initial_max_stream_data_uni'
    when 0x08 then 'initial_max_stream_bidi'
    when 0x09 then 'intial_max_stream_uni'
    when 0x0a then 'ack_delay_exponent'
    when 0x0b then 'max_ack_delay'
    when 0x0c then 'disable_active_migration'
    when 0x0d then 'preferred_address'
    when 0x0e then 'active_connection_id_limit'
    when 0x0f then 'initial_source_connection_id'
    when 0x10 then 'retry_source_connection_id'
    end
  end

  def pretty
    { params: params.map { |p| { name: param_name(p["id"]), value: p["val"] } } }
  end
end

class TlsExtension < BinData::Record
  bit16 :extension_type
  bit16 :len
  buffer :body, :length => :len do
    # https://iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    choice :selection => :extension_type do
      # https://datatracker.ietf.org/doc/html/rfc6066
      tls_server_name_extension 0

      # https://datatracker.ietf.org/doc/html/rfc8422
      tls_supported_groups_extension 10

      # https://datatracker.ietf.org/doc/html/rfc7301
      tls_application_layer_protocol_negotiation_extension 16

      # https://datatracker.ietf.org/doc/html/rfc8446
      tls_signature_algorithms_extension   13
      tls_key_share_extension              51
      tls_psk_key_exchange_modes_extension 45
      tls_supported_versions_extension     43

      # https://www.rfc-editor.org/rfc/rfc9001.html
      # https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin
      quic_transport_parameters_extension 57
    end
  end

  def extension_type_name
    case extension_type
    when 0 then 'server_name'
    when 1 then 'max_fragment_length'
    when 5 then 'status_request'
    when 10 then 'supported_groups'
    when 13 then 'signature_algorithms'
    when 14 then 'use_strp'
    when 15 then 'heartbeat'
    when 16 then 'application_layer_protocol_negotiation'
    when 18 then 'signed_certificate_timestamp'
    when 19 then 'client_certificate_type'
    when 20 then 'server_certificate_type'
    when 21 then 'padding'
    when 41 then 'pre_shared_key'
    when 42 then 'early_data'
    when 43 then 'supported_versions'
    when 44 then 'cookie'
    when 45 then 'psk_key_exchange_modes'
    when 47 then 'certificate_authorithms_cert'
    when 48 then 'old_filters'
    when 49 then 'post_handshake_auth'
    when 50 then 'signature_algorithms_cert'
    when 51 then 'key_share'
    when 57 then 'quic_transport_parameters'
    end
  end

  def pretty
    { extension_type: extension_type_name, body: body.pretty }
  end
end

class TlsClientHello < BinData::Record
  tls_protocol_version :client_version
  tls_random :random
  bit8   :session_id_length
  string :session_id, :length => :session_id_length
  bit16  :cipher_suites_length
  array  :cipher_suites, :type => :bit16, :initial_length => lambda { cipher_suites_length / 2 }
  bit8   :compression_methods_length
  array  :compression_methods, :type => :bit8, :initial_length => :compression_methods_length
  bit16  :extensions_length
  buffer :extensions, :length => :extensions_length do
    array :type => :tls_extension, :read_until => :eof
  end

  def cipher_suites_names
    cipher_suites.map do |cipher|
      case cipher
      when 0x1301 then "TLS_AES_128_GCM_SHA256"
      when 0x1302 then "TLS_AES_256_GCM_SHA384"
      when 0x1303 then "TLS_CHACHA20_POLY1305_SHA256"
      when 0x1304 then "TLS_AES_128_CCM_SHA256"
      when 0x1305 then "TLS_AES_256_CCM_8_SHA256"
      end
    end
  end

  def pretty
    {
      protocol_version: client_version,
      random: random,
      session_id: session_id,
      cipher_suites: cipher_suites_names,
      compression_methods: compression_methods,
      extensions: extensions.map { |e| e.pretty }
    }
  end
end

class TlsHandshake < BinData::Record
  bit8 :msg_type
  bit24 :len
  buffer :body, :length => :len do
    choice :selection => :msg_type do
      tls_client_hello 0x01
    end
  end

  def pretty
    msg_type_name = case msg_type
    when 1 then 'client_hello'
    when 2 then 'server_hello'
    when 4 then 'new_session_ticket'
    when 5 then 'end_of_early_data'
    when 8 then 'encrypted_extentions'
    when 11 then 'certificate'
    when 13 then 'certificate_request'
    when 15 then 'certificate_verify'
    when 20 then 'finished'
    when 24 then 'key_update'
    when 254 then 'message_hash'
    end

    { msg_type: msg_type_name, length: len, body: body.pretty }
  end
end

socket = UDPSocket.new
socket.bind("0.0.0.0", 8080)

loop do
  begin
    raw_packet, addr = socket.recvfrom_nonblock(2000)
    pp addr
  rescue IO::WaitReadable
    retry
  end
  QuicInitialPacketHeader.read(raw_packet).remove_protection(raw_packet)

  initial_packet = QuicInitialPacket.read(raw_packet)
  initial_packet.decrypt!
  pp initial_packet
  QuicFrames.read(initial_packet.payload).frames.each{|frame|
    pp frame
    if frame.frame_type == 0x6
      Pry::ColorPrinter.pp TlsHandshake.read(frame.body.data).pretty
    end
  }
end
