require 'raiha/tls/handshake'

module Raiha
  class Tls
    def parse(message)
      ::Raiha::Tls::Handshake.new(message).parse
    end
  end
end
