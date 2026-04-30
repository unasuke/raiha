# frozen_string_literal: true

module RaihaInterop
  # Catalogue of quic-interop-runner testcases raiha advertises
  # support for. Anything not listed here returns exit status 127
  # which the runner treats as "not implemented" and skips.
  module Testcases
    SUPPORTED = %w[
      handshake
      transfer
      http3
      versionnegotiation
      retry
    ].freeze

    # Testcases that change the server's behaviour rather than just
    # extending the client request set.
    SERVER_REQUIRES_RETRY = %w[retry].freeze
    REQUIRES_HTTP3 = %w[http3 transfer].freeze

    def self.supported?(name)
      SUPPORTED.include?(name)
    end

    def self.requires_retry?(name)
      SERVER_REQUIRES_RETRY.include?(name)
    end

    def self.requires_http3?(name)
      REQUIRES_HTTP3.include?(name)
    end
  end
end
