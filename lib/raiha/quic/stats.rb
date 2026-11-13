# frozen_string_literal: true

module Raiha::Next::QUIC
  # What a connection has done, as `Connection#stats` gives it. `rtt` is
  # the smoothed RTT, and it, `rtt_var`, `min_rtt` (nil before the first
  # sample), `congestion_window` and `bytes_in_flight` are the current
  # path's; `packets_spuriously_lost` counts the packets declared lost and
  # acknowledged after. `handshake_duration` is the seconds from the
  # connection's start to the handshake's completion, nil before it.
  # `receive_window` is the connection's receive window, which grows as the
  # application reads fast, and `send_buffer_bytes` the stream data not
  # sent or not acknowledged; `blocked_sent` counts the BLOCKED frames the
  # peer's limits made this end send, not those sent again, and
  # `blocked_received` those the peer sent, so that the slow end shows
  # without a qlog.
  class Stats < Data.define(
    :rtt, :rtt_var, :min_rtt, :congestion_window, :bytes_in_flight,
    :packets_sent, :packets_received, :packets_lost, :packets_spuriously_lost,
    :bytes_sent, :bytes_received,
    :path_mtu, :handshake_duration,
    :receive_window, :send_buffer_bytes, :blocked_sent, :blocked_received
  )
  end
end
