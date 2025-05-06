module Raiha
  module TLS
    class Handshake
      # Certificate message
      #
      #   enum {
      #       X509(0),
      #       RawPublicKey(2),
      #       (255)
      #   } CertificateType;
      #
      #   struct {
      #       select (certificate_type) {
      #           case RawPublicKey:
      #             /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
      #             opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
      #
      #           case X509:
      #             opaque cert_data<1..2^24-1>;
      #       };
      #       Extension extensions<0..2^16-1>;
      #   } CertificateEntry;
      #
      #   struct {
      #       opaque certificate_request_context<0..2^8-1>;
      #       CertificateEntry certificate_list<0..2^24-1>;
      #   } Certificate;
      #
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
      class Certificate < Message
        CERTIFICATE_TYPE = {
          x509: 0,
          raw_public_key: 2,
        }.freeze

        attr_accessor :certificate_request_context
        attr_accessor :opaque_certificate_data
        attr_accessor :extensions
        attr_accessor :certificate_entries

        # TODO: use Hash or Data?
        class CertificateEntry
          attr_accessor :opaque_certificate_data
          attr_accessor :extensions

          def initialize(opaque_certificate_data:, extensions:)
            @opaque_certificate_data = opaque_certificate_data
            @extensions = extensions
          end
        end

        def initialize
          @certificate_request_context = ""
          @certificate_entries = []
          @certificates = []
        end

        def self.deserialize(data)
          cert = self.new
          buf = StringIO.new(data)
          certificate_request_context_length = buf.read(1).unpack1("C")
          cert.certificate_request_context = buf.read(certificate_request_context_length)

          certificate_list_length = ("\x00" + buf.read(3)).unpack1("L>")
          certificate_list = buf.read(certificate_list_length)

          certificate_list_buf = StringIO.new(certificate_list)
          loop do
            break if certificate_list_buf.eof?

            cert_length = ("\x00" + certificate_list_buf.read(3)).unpack1("L>")
            opaque_certificate_data = certificate_list_buf.read(cert_length)
            extension_length = certificate_list_buf.read(2).unpack1("n")
            extensions = Handshake::Extension.deserialize_extensions(certificate_list_buf.read(extension_length), type: :server)
            cert.certificate_entries << CertificateEntry.new(opaque_certificate_data: opaque_certificate_data, extensions: extensions)
          end

          raise if !certificate_list_buf.eof? || !buf.eof?

          cert
        end

        def serialize
          buf = String.new(encoding: "BINARY")
          buf << [certificate_request_context.bytesize].pack("C")
          buf << certificate_request_context

          certificate_list = ""
          @certificate_entries.each do |entry|
            certificate_list += [entry.opaque_certificate_data.bytesize].pack("L>")[1..]
            certificate_list += entry.opaque_certificate_data
            certificate_list += serialize_extensions(entry.extensions)
          end

          buf << [certificate_list.bytesize].pack("L>")[1..]
          buf << certificate_list
        end

        def serialize_extensions(extensions)
          # TODO: move to abstract class?
          buf = extensions.map(&:serialize).join
          [buf.bytesize].pack("n") + buf
        end

        def certificates
          if @certificates.length != @certificate_entries.length
            @certificates = @certificate_entries.map { |entry| OpenSSL::X509::Certificate.new(entry.opaque_certificate_data) }
          else
            @certificates
          end
        end
      end
    end
  end
end
