# frozen_string_literal: true

require_relative "../codec"

module Raiha::Next::TLS
  module Extension
    # Reads an extension block, `Extension extensions<min..2^16-1>`, in the
    # given context. The two checks that need no more than the block itself
    # happen here: no type appears twice, and a registered type appears only
    # in a context its PLACEMENT row allows. A type the registry does not know
    # becomes an Opaque.
    def self.read_list(r, context:, registry:, min: 0)
      r.vector(2, min:, max: 0xffff) do |v|
        # @type var seen: Hash[Integer, true]
        seen = {}
        # @type var list: Array[_Extension]
        list = []
        until v.eof?
          type = v.u16
          data = v.opaque(2, max: 0xffff)
          raise Codec::Duplicate, "extension #{type} appears twice" if seen.key?(type)
          seen[type] = true
          list << parse_one(type, data, context, registry)
        end
        list.freeze
      end
    end

    def self.parse_one(type, data, context, registry)
      return Opaque.new(type:, data:) unless registry.registered?(type)
      parser = registry.lookup(type, context) or
        raise Codec::IllegalPlacement, "extension #{type} is not allowed in #{context}"
      parser.parse(data)
    end

    # Writes an extension block. Two extensions of the same type raise
    # EncodeError, the same condition read_list rejects.
    def self.write_list(w, extensions, min: 0)
      types = extensions.map(&:extension_type)
      raise Codec::EncodeError, "an extension type appears twice: #{types.inspect}" if types.uniq.size != types.size
      w.vector(2, min:, max: 0xffff) do
        extensions.each do |ext|
          w.u16(ext.extension_type)
          w.vector(2, max: 0xffff) { w.bytes(ext.encode) }
        end
      end
    end
  end
end
