require_relative "../../../util/io_reader"

module Raiha
  module TLS
    class Handshake
      # CertificateRequest message
      #
      #   struct {
      #       opaque certificate_request_context<0..2^8-1>;
      #       Extension extensions<2..2^16-1>;
      #   } CertificateRequest;
      #
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
      class CertificateRequest < Message
        attr_accessor :certificate_request_context
        attr_accessor :extensions

        def initialize
          @certificate_request_context = ""
          @extensions = []
        end

        def self.deserialize(data)
          req = new
          buf = StringIO.new(data)

          context_length = Raiha::Util::IOReader.read_exact(buf, 1).unpack1("C")
          req.certificate_request_context = Raiha::Util::IOReader.read_exact(buf, context_length)

          extensions_length = Raiha::Util::IOReader.read_exact(buf, 2).unpack1("n")
          req.extensions = Extension.deserialize_extensions(
            Raiha::Util::IOReader.read_exact(buf, extensions_length),
            type: :certificate_request
          )

          req
        end

        def serialize
          buf = String.new(encoding: "BINARY")
          buf << [@certificate_request_context.bytesize].pack("C")
          buf << @certificate_request_context

          ext_buf = @extensions.map(&:serialize).join
          buf << [ext_buf.bytesize].pack("n")
          buf << ext_buf

          buf
        end
      end
    end
  end
end
