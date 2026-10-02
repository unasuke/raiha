# frozen_string_literal: true

module Raiha::Next::TLS
  # Diagnostic values for the `tracer:` of a handshake, one `#tls_trace(value)`
  # call each. None of them carries a secret. A tracer ignores the kinds it
  # does not know, so new kinds do not break it, and with no tracer the
  # values are never built.
  module Trace
    class TranscriptUpdated < Data.define(:msg_type, :length, :digest)
    end

    class PskRejected < Data.define(:index, :reason)
    end

    class EarlyDataRejected < Data.define(:reason)
    end

    class TicketNotIssued < Data.define(:reason)
    end

    # A server extension of a type the client did not offer, dropped.
    class ExtensionDropped < Data.define(:type)
    end

    # An SNI that is not a valid host name, treated as absent.
    class ServerNameIgnored < Data.define(:reason)
    end

    # The client was asked for 0-RTT but did not attempt it.
    class EarlyDataNotAttempted < Data.define(:reason)
    end

    # The next four are built only where the check they name has just
    # passed, which a hygiene test enforces, so a test oracle can rely on
    # them: a completed handshake without them skipped a check.

    # The Verifier accepted the peer's chain; `purpose` is :server or
    # :client.
    class PeerCertificateVerified < Data.define(:purpose)
    end

    # The signature of the peer's CertificateVerify verified.
    class PeerSignatureVerified < Data.define(:algorithm)
    end

    # A server verified the binder of the PSK it selected.
    class BinderVerified < Data.define(:index)
    end

    # The peer's Finished verified over this transcript hash.
    class PeerFinishedVerified < Data.define(:transcript_hash)
    end
  end
end
