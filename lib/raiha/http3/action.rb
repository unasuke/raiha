# frozen_string_literal: true

module Raiha::Next::HTTP3
  # What the HTTP/3 layer asks of the transport below it besides writing
  # to streams, for whatever joins the two to do (HTTP/3 does not know
  # QUIC).
  module Action
    # Abandon sending on `stream_id`, with `error_code`.
    class Reset < Data.define(:stream_id, :error_code); end

    # Ask the peer to stop sending on `stream_id`, with `error_code`.
    class StopSending < Data.define(:stream_id, :error_code); end

    # Send `stream_id` with `urgency` and as `incremental` (RFC 9218).
    class Priority < Data.define(:stream_id, :urgency, :incremental); end

    # Close the connection with `error_code`, an application's, for
    # `reason`. Nothing more comes from this layer after it.
    class Close < Data.define(:error_code, :reason); end
  end
end
