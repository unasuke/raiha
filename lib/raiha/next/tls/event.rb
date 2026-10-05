# frozen_string_literal: true

module Raiha::Next::TLS
  # What the handshake core tells the application, as opposed to the Output
  # queue that goes to the transport.
  module Event
    # `server_name` is this ClientHello's on the server, never the one of a
    # resumed session (RFC 9846 "New Session Ticket Message").
    # `peer_verified` is false when Verifier::None let the peer in, so a test
    # setting that reaches production does not go unseen. A server reports
    # only the leaf in `peer_certificates` for a resumed connection.
    class HandshakeComplete < Data.define(
      :server_name, :alpn, :cipher_suite, :group, :resumed,
      :early_data_accepted, :peer_certificates, :peer_verified
    )
    end

    class EarlyDataRejected < Data.define(:reason)
    end

    # The client did not offer the session it was given. A reason in
    # DISCARD_REASONS means no connection can ever use it, so the application
    # may drop it from its store. `discard?` is derived from the reason so
    # the two cannot disagree.
    class SessionNotOffered < Data.define(:reason)
      DISCARD_REASONS = %i[ticket_expired certificate_expired untrusted_chain].freeze

      def discard? = DISCARD_REASONS.include?(reason)
    end

    class PeerExtension < Data.define(:type, :data, :message)
    end

    # The alert sent and a Symbol naming the check that failed. A QUIC
    # binding maps a reason listed in Profile#protocol_violation_reasons to
    # PROTOCOL_VIOLATION. The alert is nil when none was sent: over TCP, a
    # peer that closed during the handshake gets none back.
    class Failed < Data.define(:alert, :reason)
    end
  end
end
