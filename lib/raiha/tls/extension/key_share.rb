# frozen_string_literal: true

require_relative "../codec"
require_relative "../masked_inspect"

module Raiha::Next::TLS
  module Extension
    # key_share. A HelloRetryRequest carries only the group it wants, so that
    # is a class of its own and cannot hold a key.
    module KeyShare
      TYPE = 51

      # KeyShareEntry: `NamedGroup group; opaque key_exchange<1..2^16-1>`.
      class Entry < Data.define(:group, :key_exchange)
        include MaskedInspect

        def self.read(r)
          group = r.u16
          new(group:, key_exchange: r.opaque(2, min: 1, max: 0xffff))
        end

        def write(w)
          w.u16(group)
          w.vector(2, min: 1, max: 0xffff) { w.bytes(key_exchange) }
        end

        def masked_members = %i[key_exchange]
      end

      # In a ClientHello: `KeyShareEntry client_shares<0..2^16-1>`.
      class CH < Data.define(:client_shares)
        def self.parse(data)
          r = Codec::Reader.new(data)
          shares = r.vector(2, max: 0xffff) do |v|
            # @type var list: Array[Entry]
            list = []
            list << Entry.read(v) until v.eof?
            list.freeze
          end
          r.finish!
          new(client_shares: shares)
        end

        def extension_type = TYPE

        def encode
          w = Codec::Writer.new
          w.vector(2, max: 0xffff) { client_shares.each { |entry| entry.write(w) } }
          w.to_s
        end
      end

      # In a ServerHello: the single KeyShareEntry the server chose.
      class SH < Data.define(:server_share)
        def self.parse(data)
          r = Codec::Reader.new(data)
          share = Entry.read(r)
          r.finish!
          new(server_share: share)
        end

        def extension_type = TYPE

        def encode
          w = Codec::Writer.new
          server_share.write(w)
          w.to_s
        end
      end

      # In a HelloRetryRequest: `NamedGroup selected_group`.
      class HRR < Data.define(:selected_group)
        def self.parse(data)
          r = Codec::Reader.new(data)
          group = r.u16
          r.finish!
          new(selected_group: group)
        end

        def extension_type = TYPE

        def encode
          w = Codec::Writer.new
          w.u16(selected_group)
          w.to_s
        end
      end
    end
  end
end
