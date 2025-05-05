require_relative "base"

module Raiha::Quic
  module Packet
    class Initial < Base
      def parse
        bit :header_form, size: 1, type: :raw
        bit :fixed_bit, size: 1, type: :raw
        bit :long_packet_type, size: 2, type: :raw
        bit :reserved_bit, size: 2, type: :raw
        bit :packet_number_length, size: 2, type: :int
        bit :version, size: 32, type: :int
        bit :destination_connection_id_length, size: 8, type: :int
        byte :destination_connection_id, size: :destination_connection_id_length
        bit :source_connection_id_length, size: 8, type: :int
        byte :source_connection_id, size: :source_connection_id_length
        var_len_int :token_length
        bit :token, size: :token_length
        var_len_int :length
        unless protected
          byte :packet_number, size: @parsed[:packet_number_length][:value] + 1, type: :int
          byte :payload, size: :length
        end
      end

      def remove_protection
        puts self.parsed
        pn_offset = 7 + 
          @parsed[:destination_connection_id_length][:value] +
          @parsed[:source_connection_id_length][:value] +
          var_len_int_byte_length(@parsed[:length][:raw][0..1]) +
          var_len_int_byte_length(@parsed[:token_length][:raw][0..1]) +
          @parsed[:token_length][:value]
        sample_offset = pn_offset + 4
        sample = @raw[sample_offset...sample_offset+16]
        enc = OpenSSL::Cipher.new('aes-128-ecb')
        enc.encrypt

        enc.key = ["9f50449e04a0e810283a1e9933adedd2"].pack("H*") # hp

        mask = ""
        mask << enc.update(sample)
        mask << enc.final

        # https://www.rfc-editor.org/rfc/rfc9001#name-header-protection-applicati
        # headerを保護するときとは逆の手順を踏んで保護を解除する
        @raw[0] = [(@raw[0].unpack1('H*').to_i(16) ^ (mask[0].unpack1('H*').to_i(16) & 0x0f)).to_s(16)].pack("H*")

        # https://www.rfc-editor.org/rfc/rfc9001#figure-6
        pn_length = (@raw[0].unpack1('H*').to_i(16) & 0x03) + 1

        packet_number =
          (@raw[pn_offset...pn_offset+pn_length].unpack1("H*").to_i(16) ^ mask[1...1+pn_length].unpack1("H*").to_i(16)).to_s(16)

        # 先頭の0が消えてしまうので、パケット番号の長さに満たないぶんを zero fillする
        @raw[pn_offset...pn_offset+pn_length] = [("0" * (pn_length * 2 - packet_number.length)) + packet_number].pack("H*")
        self.class.new(@raw, protected: false).tap {|p| p.parse}
      end
    end
  end
end
