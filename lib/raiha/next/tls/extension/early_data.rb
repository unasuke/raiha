# frozen_string_literal: true

require_relative "../codec"

module Raiha::Next::TLS
  module Extension
    # early_data.
    module EarlyData
      TYPE = 42

      # In a ClientHello: empty.
      class CH < Data.define
        def self.parse(data)
          Codec::Reader.new(data).finish!
          new
        end

        def extension_type = TYPE

        def encode = "".b
      end

      # In EncryptedExtensions: empty, accepting 0-RTT.
      class EE < Data.define
        def self.parse(data)
          Codec::Reader.new(data).finish!
          new
        end

        def extension_type = TYPE

        def encode = "".b
      end

      # In a NewSessionTicket: `uint32 max_early_data_size`.
      class NST < Data.define(:max_early_data_size)
        def self.parse(data)
          r = Codec::Reader.new(data)
          size = r.u32
          r.finish!
          new(max_early_data_size: size)
        end

        def extension_type = TYPE

        def encode
          w = Codec::Writer.new
          w.u32(max_early_data_size)
          w.to_s
        end
      end
    end
  end
end
