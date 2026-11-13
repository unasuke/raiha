# frozen_string_literal: true

require_relative "../codec"
require_relative "../extension"
require_relative "message"
require_relative "violation"

module Raiha::TLS
  module Handshake
    class EncryptedExtensions < Data.define(:extensions)
      include Message
      include ExtensionLookup

      MSG_TYPE = 8

      def self.parse_body(body, registry:)
        r = Codec::Reader.new(body)
        extensions = Extension.read_list(r, context: :encrypted_extensions, registry:)
        r.finish!
        new(extensions:)
      end

      def msg_type = MSG_TYPE

      # Nothing to check without context.
      def validate = nil

      def write_body(w)
        Extension.write_list(w, extensions)
      end
    end
  end
end
