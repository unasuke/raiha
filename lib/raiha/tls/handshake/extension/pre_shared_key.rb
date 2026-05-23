require_relative "../../../util/io_reader"
require_relative "abstract_extension"

module Raiha
  module TLS
    class Handshake
      class Extension
        # PreSharedKey Extension
        #
        #   struct {
        #       opaque identity<1..2^16-1>;
        #       uint32 obfuscated_ticket_age;
        #   } PskIdentity;
        #
        #   opaque PskBinderEntry<32..255>;
        #
        #   struct {
        #       PskIdentity identities<7..2^16-1>;
        #       PskBinderEntry binders<33..2^16-1>;
        #   } OfferedPsks;
        #
        #   struct {
        #       select (Handshake.msg_type) {
        #           case client_hello: OfferedPsks;
        #           case server_hello: uint16 selected_identity;
        #       };
        #   } PreSharedKeyExtension;
        #
        # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
        class PreSharedKey < AbstractExtension
          EXTENSION_TYPE_NUMBER = 41

          PskIdentity = Struct.new(:identity, :obfuscated_ticket_age)

          attr_accessor :identities
          attr_accessor :binders
          attr_accessor :selected_identity

          def initialize(on:)
            super
            @identities = [] #: Array[untyped]
            @binders = [] #: Array[String]
            @selected_identity = nil
          end

          def extension_data=(data)
            super
            buf = StringIO.new(data)

            case @on
            when :client_hello
              deserialize_offered_psks(buf)
            when :server_hello
              @selected_identity = Raiha::Util::IOReader.read_exact(buf, 2).unpack1("n")
            end
          end

          def serialize
            case @on
            when :client_hello
              buf = serialize_offered_psks
              [EXTENSION_TYPE_NUMBER].pack("n") + [buf.bytesize].pack("n") + buf
            when :server_hello
              buf = [@selected_identity].pack("n")
              [EXTENSION_TYPE_NUMBER].pack("n") + [buf.bytesize].pack("n") + buf
            end
          end

          private def deserialize_offered_psks(buf)
            identities_length = Raiha::Util::IOReader.read_exact(buf, 2).unpack1("n")
            identities_buf = StringIO.new(Raiha::Util::IOReader.read_exact(buf, identities_length))
            until identities_buf.eof?
              identity_length = Raiha::Util::IOReader.read_exact(identities_buf, 2).unpack1("n")
              identity = Raiha::Util::IOReader.read_exact(identities_buf, identity_length)
              obfuscated_ticket_age = Raiha::Util::IOReader.read_exact(identities_buf, 4).unpack1("N")
              @identities << PskIdentity.new(identity, obfuscated_ticket_age)
            end

            binders_length = Raiha::Util::IOReader.read_exact(buf, 2).unpack1("n")
            binders_buf = StringIO.new(Raiha::Util::IOReader.read_exact(buf, binders_length))
            until binders_buf.eof?
              binder_length = Raiha::Util::IOReader.read_exact(binders_buf, 1).unpack1("C")
              @binders << Raiha::Util::IOReader.read_exact(binders_buf, binder_length)
            end
          end

          private def serialize_offered_psks
            identities_buf = String.new(encoding: "BINARY")
            @identities.each do |psk_identity|
              identities_buf << [psk_identity.identity.bytesize].pack("n")
              identities_buf << psk_identity.identity
              identities_buf << [psk_identity.obfuscated_ticket_age].pack("N")
            end

            binders_buf = String.new(encoding: "BINARY")
            @binders.each do |binder|
              binders_buf << [binder.bytesize].pack("C")
              binders_buf << binder
            end

            [identities_buf.bytesize].pack("n") + identities_buf +
              [binders_buf.bytesize].pack("n") + binders_buf
          end
        end
      end
    end
  end
end
