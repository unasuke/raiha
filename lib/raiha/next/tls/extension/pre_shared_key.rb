# frozen_string_literal: true

require_relative "../codec"
require_relative "../masked_inspect"

module Raiha::Next::TLS
  module Extension
    # pre_shared_key.
    module PreSharedKey
      TYPE = 41

      # PskIdentity: `opaque identity<1..2^16-1>; uint32 obfuscated_ticket_age`.
      class Identity < Data.define(:identity, :obfuscated_ticket_age)
        def self.read(r)
          identity = r.opaque(2, min: 1, max: 0xffff)
          new(identity:, obfuscated_ticket_age: r.u32)
        end

        def write(w)
          w.vector(2, min: 1, max: 0xffff) { w.bytes(identity) }
          w.u32(obfuscated_ticket_age)
        end
      end

      # In a ClientHello: `PskIdentity identities<7..2^16-1>` and
      # `PskBinderEntry binders<33..2^16-1>` of `opaque PskBinderEntry<32..255>`.
      class CH < Data.define(:identities, :binders)
        include MaskedInspect

        def self.parse(data)
          r = Codec::Reader.new(data)
          identities = r.vector(2, min: 7, max: 0xffff) do |v|
            # @type var list: Array[Identity]
            list = []
            list << Identity.read(v) until v.eof?
            list.freeze
          end
          binders = r.vector(2, min: 33, max: 0xffff) do |v|
            # @type var list: Array[String]
            list = []
            list << v.opaque(1, min: 32, max: 255) until v.eof?
            list.freeze
          end
          r.finish!
          new(identities:, binders:)
        end

        def extension_type = TYPE

        def encode
          w = Codec::Writer.new
          w.vector(2, min: 7, max: 0xffff) { identities.each { |identity| identity.write(w) } }
          w.vector(2, min: 33, max: 0xffff) do
            binders.each { |binder| w.vector(1, min: 32, max: 255) { w.bytes(binder) } }
          end
          w.to_s
        end

        def masked_members = %i[binders]
      end

      # In a ServerHello: `uint16 selected_identity`.
      class SH < Data.define(:selected_identity)
        def self.parse(data)
          r = Codec::Reader.new(data)
          selected = r.u16
          r.finish!
          new(selected_identity: selected)
        end

        def extension_type = TYPE

        def encode
          w = Codec::Writer.new
          w.u16(selected_identity)
          w.to_s
        end
      end
    end
  end
end
