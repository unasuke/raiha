# frozen_string_literal: true

require_relative "placement"

module Raiha::Next::TLS
  module Extension
    # The extensions a connection can parse, by type and context. `Config`
    # holds one; nothing reads a global table. The built-in extensions are
    # registered the same way an outside one is, so `BUILTIN.with` is all it
    # takes to add, say, quic_transport_parameters.
    #
    # A module passed to `#with` defines `TYPE` and `CODECS`, a Hash from
    # context to an object whose `parse(extension_data)` returns a value with
    # `#extension_type` and `#encode`.
    class Registry < Data.define(:codecs)
      CONTEXTS = %i[
        client_hello server_hello hello_retry_request encrypted_extensions certificate
        certificate_request new_session_ticket certificate_entry
      ].freeze

      def lookup(type, context) = codecs[type]&.[](context)

      def registered?(type) = codecs.key?(type)

      # A new Registry with the extensions defined by `modules` added. A type
      # that is already registered raises ArgumentError instead of replacing
      # the existing one.
      def with(*modules)
        # @type var added: Hash[Integer, Hash[Handshake::context, _Parser]]
        added = {}
        modules.each do |mod|
          type = mod.const_get(:TYPE)
          by_context = mod.const_get(:CODECS)
          raise ArgumentError, "#{mod}::TYPE must be an Integer in 0..65535" unless type.is_a?(Integer) && type.between?(0, 0xffff)
          raise ArgumentError, "extension #{type} is already registered" if registered?(type) || added.key?(type)
          raise ArgumentError, "#{mod}::CODECS must be a Hash" unless by_context.is_a?(Hash)
          unknown = by_context.keys - CONTEXTS
          raise ArgumentError, "#{mod}::CODECS has unknown contexts: #{unknown.inspect}" unless unknown.empty?
          # A copy, so that making it shareable does not freeze the caller's Hash.
          added[type] = by_context.dup
        end
        Registry.new(codecs: Ractor.make_shareable(codecs.merge(added)))
      rescue Ractor::Error => e
        raise ArgumentError, "an extension codec cannot be shared between Ractors: #{e.message}"
      end

      BUILTIN = new(codecs: PLACEMENT)
    end
  end
end
