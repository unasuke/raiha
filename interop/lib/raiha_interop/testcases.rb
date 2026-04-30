# frozen_string_literal: true

module RaihaInterop
  # Catalogue of quic-interop-runner testcases raiha advertises
  # support for. Anything not listed here returns exit status 127
  # which the runner treats as "not implemented" and skips.
  module Testcases
    SUPPORTED = %w[
      handshake
    ].freeze

    def self.supported?(name)
      SUPPORTED.include?(name)
    end
  end
end
