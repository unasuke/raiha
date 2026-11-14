# frozen_string_literal: true

require_relative "../codec"

module Raiha::TLS
  module Handshake
    # What every handshake message value shares: `#encode` writes the 4-byte
    # header (msg_type and a 3-byte length) around `#write_body`.
    module Message
      def encode
        w = Codec::Writer.new
        w.u8(msg_type)
        w.vector(3) { write_body(w) }
        w.to_s
      end
    end

    # `#extension(type)` for a message that carries an extension block. The
    # block is an Array rather than a Hash so that its order and any
    # duplicate stay representable.
    module ExtensionLookup
      def extension(type) = extensions.find { |ext| ext.extension_type == type }
    end
  end
end
