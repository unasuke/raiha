require "bindata"

class QUICPacket < BinData::Record
  # Initial Packet {
  #   Header Form (1) = 1,
  #   Fixed Bit (1) = 1,
  #   Long Packet Type (2) = 0,
  #   Reserved Bits (2),
  #   Packet Number Length (2),
  #   Version (32),
  #   Destination Connection ID Length (8),
  #   Destination Connection ID (0..160),
  #   Source Connection ID Length (8),
  #   Source Connection ID (0..160),
  #   Token Length (i),
  #   Token (..),
  #   Length (i),
  #   Packet Number (8..32),
  #   Packet Payload (8..),
  # }
  endian :big
  bit1 :header_form, asserted_value: 1
  bit1 :fixed_bit, asserted_value: 1
  bit2 :long_packet_type, asserted_value: 0
  bit2 :reserved_bit
  bit2 :packet_number_length
  bit32 :version
  bit8 :destination_connection_id_length
  bit :destination_connection_id, nbits:  lambda { destination_connection_id_length * 8 }
  bit8 :source_connection_id_length
  bit :source_connection_id, nbits: lambda{ source_connection_id_length * 8 }
  # Variable-Length Integer Encoding for token
  bit2 :token_two_most_significant_bits
  bit :token_length, nbits: lambda {
    case token_two_most_significant_bits
    when 0
      6
    when 1
      14
    when 2
      30
    when 3
      62
    end
  }
  bit :token, nbits: :token_length

  # Variable-Length Integer Encoding for length
  bit2 :length_two_most_significant_bits
  bit :length_length, nbits: lambda {
    case length_two_most_significant_bits
    when 0
      6
    when 1
      14
    when 2
      30
    when 3
      62
    end
  }

  bit :packet_number, nbits: lambda { (packet_number_length + 1) * 8 }
  bit :payload, nbits: lambda { length_length * 8 }


  string :nokori
end

class Diagram
  attr_reader :metadata, :diagram

  def initialize(packet:)
    @packet = packet.unpack("B*")[0]
    @quic_packet = QUICPacket.read(packet)

  #   File.open("success-#{Time.now.strftime('%Y-%m-%d_%H-%M-%S')}.log", "w") do |f|
  #     f.puts format
  #   end

  #   @quic_packet

  # rescue EOFError => e
  #   pp @packet
  #   File.open("fail-#{Time.now.strftime('%Y-%m-%d_%H-%M-%S')}.log", "w") do |f|
  #     f.puts format
  #   end
  end

  def analyze
    @diagram = format
    @metadata = parse_metadata
    self
  end

  def format
    out = "|----|----|----|----|----|----|----|----|\n"

    bitcount = 0
    line = "|"
    # pp @packet
    @packet.chars.each do |bit|
      line.concat(bit.to_s)
      bitcount += 1

      if bitcount % 4 == 0
        line.concat("|")

        if bitcount % 32 == 0
          out.concat(line, "\n")
          line = "|"
        end
      end
    end

    out
  end

  def parse_metadata
    metadata = {}
    metadata[:source_port] = @packet.chars[0..15].join('').to_i(2)
    metadata[:destination_port] = @packet.chars[16..31].join('').to_i(2)
    metadata[:data_length] = @packet.chars[32..47]&.join('')&.to_i(2)
    metadata[:checksum] = @packet.chars[48..63]&.join('')&.to_i(2)
    data = ""
    @packet.chars[64..]&.each_slice(8) do |byte|
      data += byte.join('').to_i(2).chr
    end
    metadata[:header_type] = @packet[0..1] == "11" ? :long : :short
    metadata[:packet_type] = case @packet[2..3]
    when "00"
      :initial
    when "01"
      :'0-RTT'
    when "02"
      :handshake
    when "03"
      :retry
    end

    # metadata[:data] = data
    # binding.irb
    pp @quic_packet
    metadata
  end
end
