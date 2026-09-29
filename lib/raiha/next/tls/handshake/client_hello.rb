# frozen_string_literal: true

require_relative "../codec"
require_relative "../extension"
require_relative "message"

module Raiha::Next::TLS
  module Handshake
    class ClientHello < Data.define(
      :legacy_version, :random, :legacy_session_id, :cipher_suites, :legacy_compression_methods, :extensions
    )
      include Message
      include ExtensionLookup

      MSG_TYPE = 1

      def self.parse_body(body, registry:)
        r = Codec::Reader.new(body)
        legacy_version = r.u16
        random = r.bytes(32)
        legacy_session_id = r.opaque(1, max: 32)
        cipher_suites = r.vector(2, min: 2, max: 0xfffe) do |v|
          # @type var list: Array[Integer]
          list = []
          list << v.u16 until v.eof?
          list.freeze
        end
        legacy_compression_methods = r.opaque(1, min: 1, max: 0xff).bytes.freeze
        extensions = Extension.read_list(r, context: :client_hello, registry:, min: 7)
        r.finish!
        new(legacy_version:, random:, legacy_session_id:, cipher_suites:, legacy_compression_methods:, extensions:)
      end

      def msg_type = MSG_TYPE

      def write_body(w)
        w.u16(legacy_version)
        w.bytes(random)
        w.vector(1, max: 32) { w.bytes(legacy_session_id) }
        w.vector(2, min: 2, max: 0xfffe) { cipher_suites.each { |suite| w.u16(suite) } }
        w.vector(1, min: 1, max: 0xff) { legacy_compression_methods.each { |method| w.u8(method) } }
        Extension.write_list(w, extensions, min: 7)
      end

      # Raises EncodeError when pre_shared_key is present but not last, which
      # RFC 9846 requires of a ClientHello.
      def encode
        psk_index = extensions.index { |ext| ext.extension_type == Extension::PreSharedKey::TYPE }
        if psk_index && psk_index != extensions.size - 1
          raise Codec::EncodeError, "pre_shared_key must be the last extension"
        end
        super
      end

      # The number of bytes the binders list takes at the end of the encoded
      # ClientHello: its 2-byte length and each binder with its 1-byte length.
      # Zero without pre_shared_key.
      def binders_wire_length
        case (psk = extension(Extension::PreSharedKey::TYPE))
        when Extension::PreSharedKey::CH
          2 + psk.binders.sum { |binder| 1 + binder.bytesize }
        else
          0
        end
      end

      # The encoded ClientHello up to, but not including, the binders list: the
      # input to the binder MAC. Encode the ClientHello with placeholder
      # binders of the right lengths first, so every length field in front is
      # final, then fill the real binders in with `#with_binders`.
      def encode_truncated
        full = encode
        full.byteslice(0, full.bytesize - binders_wire_length) #: String
      end

      # This ClientHello with the pre_shared_key binders replaced. Each binder
      # must be as long as the one it replaces, or the truncated ClientHello
      # the binders were computed over would no longer match.
      def with_binders(binders)
        found = false
        replaced = extensions.map do |ext|
          case ext
          when Extension::PreSharedKey::CH
            found = true
            unless binders.map(&:bytesize) == ext.binders.map(&:bytesize)
              raise ArgumentError, "binder lengths #{binders.map(&:bytesize)} differ from #{ext.binders.map(&:bytesize)}"
            end
            ext.with(binders: binders.freeze)
          else
            ext
          end
        end
        raise ArgumentError, "this ClientHello has no pre_shared_key" unless found
        with(extensions: replaced.freeze)
      end
    end
  end
end
