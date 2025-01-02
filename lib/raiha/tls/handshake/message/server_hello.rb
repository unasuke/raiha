require "securerandom"
require_relative "../extension"

module Raiha
  module TLS
    class Handshake
      class ServerHello < Message
        # @see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
        HELLO_RETRY_REQUEST_RANDOM = [<<~RANDOM.gsub(/[[:space:]]/, '')].pack("H*")
          cf 21 ad 74 e5 9a 61 11 be 1d 8c 02 1e 65 b8 91
          c2 a2 11 16 7a bb 8c 5e 07 9e 09 e2 c8 a8 33 9c
        RANDOM

        attr_accessor :random
        attr_accessor :legacy_session_id_echo
        attr_accessor :cipher_suite
        attr_accessor :extensions

        def self.respond_to_client_hello(client_hello)
          sh = self.new
          sh.random = SecureRandom.random_bytes(32)
          sh
        end

        def serialize
        end
      end
    end
  end
end
