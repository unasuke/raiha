require "stringio"
require_relative "../record"

module Raiha
  module TLS
    class Record
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
      class TLSCiphertext
        attr_accessor :tls_inner_plaintext

        def initialize
          @content_type = CONTENT_TYPE[:application_data]
          @protocol_version = [0x03, 0x03].pack("C*") # TLS v1.2
        end

        def serialize
        end
      end
    end
  end
end
