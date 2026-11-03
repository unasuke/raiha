# frozen_string_literal: true

module Raiha::Next::QUIC
  module Congestion
    # NewReno as RFC 9002 "Congestion Control" and its appendix B describe
    # it. The window grows by the bytes acknowledged in slow start and by
    # one datagram a window in congestion avoidance; a loss or an ECN-CE
    # halves it once a round trip, or an ECN-CE alone multiplies it by the
    # Config's beta_ecn when there is one, and persistent congestion takes
    # it to the minimum, back into slow start.
    #
    # Loss recovery calls it once an ACK frame, not once a packet: the
    # recovery period ends with the first ACK whose largest acknowledged
    # packet was sent after the period began.
    class NewReno
      # kLossReductionFactor, as a divisor of the window.
      LOSS_REDUCTION_DIVISOR = 2

      # No rate samples: the window is all it needs.
      def self.requires_rate_sample? = false

      # Bytes.
      attr_reader :window

      # `initial_window` turns a maximum datagram size into the initial
      # window, so that it can be worked out again when the size changes.
      # `config` is the connection's Config, which an algorithm reads its own
      # settings from.
      def initialize(max_datagram_size:, initial_window:, config:, tracer: nil)
        @max_datagram_size = max_datagram_size
        @initial_window = initial_window
        @beta_ecn = config.beta_ecn
        @window = initial_window.call(max_datagram_size)
        @ssthresh = nil #: Integer?
        @recovery_start = nil #: Float?
        @in_recovery = false
        @app_limited = false
        # Whether the window is still the initial one.
        @initial = true
        @state = :slow_start
        @tracer = tracer
        # The smoothed RTT once there is an RTT sample, which pacing waits
        # for.
        @smoothed_rtt = nil #: Float?
      end

      def minimum_window = 2 * @max_datagram_size

      def on_packet_sent(bytes:, now:) = nil

      def on_ack(acked_bytes:, largest_acked_sent_at:, latest_rtt:, smoothed_rtt:, min_rtt:, app_limited:, now:, rate_sample: nil)
        @smoothed_rtt = smoothed_rtt if min_rtt
        start = @recovery_start
        @in_recovery = false if start && largest_acked_sent_at > start
        @app_limited = app_limited
        unless @in_recovery || app_limited
          @window += slow_start? ? acked_bytes : @max_datagram_size * acked_bytes / @window
          @initial = false
        end
        update_state(now)
      end

      # `persistent` takes the window to the minimum even within a recovery
      # period, and ends the period (RFC 9002 "Persistent Congestion").
      def on_loss(lost_bytes:, largest_lost_sent_at:, persistent:, now:)
        congestion_event(largest_lost_sent_at, now)
        if persistent
          @window = minimum_window
          @recovery_start = nil
          @in_recovery = false
        end
        update_state(now)
      end

      def on_ecn_ce(largest_acked_sent_at:, now:)
        congestion_event(largest_acked_sent_at, now, beta: @beta_ecn)
        update_state(now)
      end

      # The minimum window follows the size, and an initial window not yet
      # moved is worked out again (RFC 9002 "Initial and Minimum Congestion
      # Window").
      def on_mtu_updated(max_datagram_size:, now:)
        @max_datagram_size = max_datagram_size
        @window = @initial_window.call(max_datagram_size) if @initial
        @window = [@window, minimum_window].max
      end

      # Bytes a second (Pacing), nil until there is an RTT sample: the
      # initial window may go at once before then (RFC 9002 "Pacing").
      def pacing_rate = (rtt = @smoothed_rtt) && Pacing.rate(@window, rtt, slow_start: slow_start?)

      # :slow_start, :congestion_avoidance, :recovery or :application_limited.
      attr_reader :state

      def metrics
        metrics = { congestion_window: @window } #: Hash[Symbol, Integer]
        metrics[:ssthresh] = @ssthresh if @ssthresh # steep:ignore
        rate = pacing_rate
        # qlog has it in bits a second.
        metrics[:pacing_rate] = (rate * 8).to_i if rate
        metrics
      end

      private def slow_start?
        ssthresh = @ssthresh
        ssthresh.nil? || @window < ssthresh
      end

      # RFC 9002 appendix B "On New Congestion Event": nothing for a packet
      # sent before the current recovery period began. The window is halved,
      # or multiplied by `beta` when there is one.
      private def congestion_event(sent_at, now, beta: nil)
        start = @recovery_start
        return if start && sent_at <= start
        @recovery_start = now
        @in_recovery = true
        @initial = false
        ssthresh = @ssthresh = beta ? (@window * beta).to_i : @window / LOSS_REDUCTION_DIVISOR
        @window = [ssthresh, minimum_window].max
      end

      private def update_state(now)
        state = if @in_recovery then :recovery
          elsif @app_limited then :application_limited
          elsif slow_start? then :slow_start
          else :congestion_avoidance
          end
        return if state == @state
        @tracer.congestion_state_updated(old: @state, new: state, now:) if @tracer # steep:ignore
        @state = state
      end
    end
  end
end
