# frozen_string_literal: true

require "openssl"

module Raiha
  module TLS
    class TrustStore
      def initialize
        @store = OpenSSL::X509::Store.new
        @store.set_default_paths
      end

      def add_cert(cert)
        @store.add_cert(cert)
        self
      end

      def add_file(path)
        @store.add_file(path)
        self
      end

      def verify(cert, chain: [])
        store = @store.dup
        chain.each { |c| store.add_cert(c) }
        store.verify(cert)
      end
    end
  end
end
