# frozen_string_literal: true

require_relative "../codec"
require_relative "../extension"
require_relative "message"
require_relative "violation"

module Raiha::TLS
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
        extensions = Extension.read_list(r, context: :client_hello, registry:, min: 8)
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
        Extension.write_list(w, extensions, min: 8)
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

      # The checks a server makes on a ClientHello by itself, in order; the
      # first failure is returned. The order is part of the rules:
      #
      # 1. Versions first. Only after 2 is it a ClientHello offering TLS 1.3,
      #    to which the extension requirements in 4 to 6 apply.
      # 2. missing_extension before illegal_parameter: check that an extension
      #    is there before looking inside it. 9 reads both supported_groups and
      #    key_share, so it relies on 5 having passed.
      # 3. 9 runs only when key_share is present. A PSK-only ClientHello has
      #    neither extension, passes 5, and 9 finds nothing to check.
      #
      # Requiring key_share to list groups in supported_groups order is left
      # out on purpose, to avoid ossification.
      def validate
        # 1
        return Violation.new(alert: :protocol_version, reason: :legacy_version) unless legacy_version == 0x0303
        # 2. Without supported_versions a server would have to negotiate TLS 1.2
        # or lower, which this implementation cannot.
        versions = supported_versions_extension
        unless versions && versions.versions.include?(0x0304)
          return Violation.new(alert: :protocol_version, reason: :supported_versions)
        end
        # 3
        unless legacy_compression_methods == [0]
          return Violation.new(alert: :illegal_parameter, reason: :legacy_compression_methods)
        end
        groups = supported_groups_extension
        key_share = key_share_extension
        psk = pre_shared_key_extension
        # 4
        if psk.nil? && signature_algorithms_extension.nil?
          return Violation.new(alert: :missing_extension, reason: :signature_algorithms)
        end
        return Violation.new(alert: :missing_extension, reason: :supported_groups) if psk.nil? && groups.nil?
        # 5
        if key_share && groups.nil?
          return Violation.new(alert: :missing_extension, reason: :key_share_without_supported_groups)
        end
        if groups && key_share.nil?
          return Violation.new(alert: :missing_extension, reason: :supported_groups_without_key_share)
        end
        # 6
        if psk && psk_key_exchange_modes_extension.nil?
          return Violation.new(alert: :missing_extension, reason: :psk_key_exchange_modes)
        end
        # 7
        if groups && groups.named_group_list.uniq.size != groups.named_group_list.size
          return Violation.new(alert: :illegal_parameter, reason: :duplicate_supported_group)
        end
        if key_share
          share_groups = key_share.client_shares.map(&:group)
          # 8
          if share_groups.uniq.size != share_groups.size
            return Violation.new(alert: :illegal_parameter, reason: :duplicate_key_share_group)
          end
          # 9. GREASE groups pass: RFC 8701 puts them in supported_groups too.
          unless groups && (share_groups - groups.named_group_list).empty?
            return Violation.new(alert: :illegal_parameter, reason: :key_share_group_not_supported)
          end
        end
        if psk
          # 10
          unless psk.equal?(extensions.last)
            return Violation.new(alert: :illegal_parameter, reason: :pre_shared_key_not_last)
          end
          # 11
          unless psk.binders.size == psk.identities.size
            return Violation.new(alert: :illegal_parameter, reason: :binders_count)
          end
        end
        nil
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

      private def supported_versions_extension
        case (ext = extension(Extension::SupportedVersions::TYPE))
        when Extension::SupportedVersions::CH then ext
        end
      end

      private def supported_groups_extension
        case (ext = extension(Extension::SupportedGroups::TYPE))
        when Extension::SupportedGroups then ext
        end
      end

      private def key_share_extension
        case (ext = extension(Extension::KeyShare::TYPE))
        when Extension::KeyShare::CH then ext
        end
      end

      private def pre_shared_key_extension
        case (ext = extension(Extension::PreSharedKey::TYPE))
        when Extension::PreSharedKey::CH then ext
        end
      end

      private def signature_algorithms_extension
        case (ext = extension(Extension::SignatureAlgorithms::TYPE))
        when Extension::SignatureAlgorithms then ext
        end
      end

      private def psk_key_exchange_modes_extension
        case (ext = extension(Extension::PskKeyExchangeModes::TYPE))
        when Extension::PskKeyExchangeModes then ext
        end
      end
    end
  end
end
