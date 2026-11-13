# frozen_string_literal: true

module Raiha::HTTP3
  # What happened on an HTTP/3 connection, for the application.
  module Event
    # The peer's settings came (Settings).
    class Settings < ::Data.define(:settings); end

    # A field section came on `stream_id`: a request's, a response's or an
    # interim response's, as [name, value] pairs, the pseudo-header fields
    # first. `fin` if the stream ended with it.
    class Headers < ::Data.define(:stream_id, :headers, :fin)
      def initialize(stream_id:, headers:, fin:)
        headers = Ractor.make_shareable(headers.map(&:dup))
        super
      end
    end

    # Content came on `stream_id`, as it arrived; `fin` if the stream ended
    # with it, which may come with no content.
    class Data < ::Data.define(:stream_id, :data, :fin); end

    # The trailer section of the message on `stream_id` came, which ends
    # it.
    class Trailers < ::Data.define(:stream_id, :headers)
      def initialize(stream_id:, headers:)
        headers = Ractor.make_shareable(headers.map(&:dup))
        super
      end
    end

    # What the peer sends on `stream_id` ended with `error_code`, the peer
    # having reset it, or this layer having stopped the stream, after the
    # application had heard of it.
    class Reset < ::Data.define(:stream_id, :error_code); end

    # The peer asked this end to stop sending on `stream_id`, with
    # `error_code`; nothing more goes on it, though the peer's side may
    # still come.
    class Stopped < ::Data.define(:stream_id, :error_code); end

    # `send_data` takes content on `stream_id` again, after it took less
    # than given.
    class Writable < ::Data.define(:stream_id); end

    # A Capsule other than DATAGRAM came on `stream_id` (RFC 9297 "The
    # Capsule Protocol").
    class Capsule < ::Data.define(:stream_id, :capsule); end

    # An HTTP Datagram for the request on `stream_id` came (RFC 9297), in a
    # DATAGRAM of the transport or a DATAGRAM Capsule.
    class Datagram < ::Data.define(:stream_id, :payload); end

    # The peer goes away (RFC 9114 "Connection Shutdown"): a server's
    # `stream_id`, from which on requests were not processed, or a
    # client's push ID.
    class GoAway < ::Data.define(:stream_id); end

    # The field section on `stream_id` waits for entries the QPACK encoder
    # stream has yet to bring (RFC 9204 "Blocked Decoding").
    class Blocked < ::Data.define(:stream_id); end
  end
end
