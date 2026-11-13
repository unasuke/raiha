# frozen_string_literal: true

require_relative "../codec"

module Raiha::TLS
  module Extension
    # supported_groups: `NamedGroup named_group_list<2..2^16-1>`.
    class SupportedGroups < Data.define(:named_group_list)
      TYPE = 10

      def self.parse(data)
        r = Codec::Reader.new(data)
        groups = r.vector(2, min: 2, max: 0xffff) do |v|
          # @type var list: Array[Integer]
          list = []
          list << v.u16 until v.eof?
          list.freeze
        end
        r.finish!
        new(named_group_list: groups)
      end

      def extension_type = TYPE

      def encode
        w = Codec::Writer.new
        w.vector(2, min: 2, max: 0xffff) { named_group_list.each { |group| w.u16(group) } }
        w.to_s
      end
    end
  end
end
