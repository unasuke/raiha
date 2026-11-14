# frozen_string_literal: true

module Raiha::TLS
  module Verifier
    # Accepts any chain. For tests only: a handshake that used it reports
    # `peer_verified: false` in Event::HandshakeComplete, so it shows if it
    # reaches production.
    class None
      def verify(chain:, server_name:, now:, purpose:) = Result.new(ok: true, reason: nil, verified_chain: chain)

      def resumption_policy = "none"
    end
  end
end
