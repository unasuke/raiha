# frozen_string_literal: true

module Raiha::Next::QUIC
  # What a connection tells the application. An event says that something
  # can be done (a stream has data to read) rather than carrying the data,
  # so flow control credit goes back as the application reads.
  module Event
    # The handshake completed. `handshake` is the TLS layer's
    # Event::HandshakeComplete, not a copy of its fields.
    class Connected < Data.define(:handshake)
    end

    class StreamReadable < Data.define(:stream_id)
    end

    # Once, when a stream that took part of a write can take more.
    class StreamWritable < Data.define(:stream_id)
    end

    class StreamReset < Data.define(:stream_id, :error_code, :final_size)
    end

    class StopSending < Data.define(:stream_id, :error_code)
    end

    class DatagramReceived < Data.define(:data)
    end

    class PathValidated < Data.define(:local, :remote)
    end

    class KeyUpdated < Data.define(:phase)
    end

    # A ticket the client may resume later, as a QUIC::Session; keeping it
    # is the application's.
    class SessionTicket < Data.define(:session)
    end

    # A token the server gave in a NEW_TOKEN frame, for the Initials of a
    # later connection to it (Endpoint#connect(token:)); keeping it is the
    # application's.
    class NewToken < Data.define(:token)
    end

    # A TLS event the binding does not consume itself, passed on as it came.
    class TLSEvent < Data.define(:event)
    end

    # The connection ended; `error` is a ConnectionError.
    class Closed < Data.define(:error, :by_peer)
    end
  end
end
