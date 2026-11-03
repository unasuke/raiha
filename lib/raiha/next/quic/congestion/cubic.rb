# frozen_string_literal: true

module Raiha::Next::QUIC
  module Congestion
    # CUBIC as RFC 9438 describes it. Slow start is Reno's. In congestion
    # avoidance the window follows the cubic function of the time since the
    # avoidance stage began,
    #
    #   W_cubic(t) = C * (t - K)^3 + W_max
    #
    # which is flat around W_max, the window before the last reduction: it
    # grows towards W_cubic(t + smoothed RTT), at most to 1.5 times the
    # window, each ACK frame (the concave region below W_max and the convex
    # region above it), and never below W_est, the window an AIMD sender
    # with the same reduction would have (the Reno-friendly region). A loss
    # or an ECN-CE multiplies the window by 0.7 once a round trip, by the
    # Config's beta_ecn for an ECN-CE alone when there is one, and with fast
    # convergence lowers W_max further when the window is below it.
    # Persistent congestion takes the window to the minimum, back into slow
    # start, and the stage after it starts from where the window is.
    #
    # The window is cut from itself, not from the bytes in flight; the
    # time `t` stands still while the connection is application-limited, so
    # that the window does not jump after an idle period (RFC 9438
    # "Window Increase Function").
    #
    # Windows are bytes here, the segments of RFC 9438 times the maximum
    # datagram size; the window is kept as a Float, so that the small growth
    # of an ACK is not lost, and given as an Integer.
    class Cubic
      # β_cubic, the factor a congestion event multiplies the window by.
      BETA = 0.7
      # C, in segments a second cubed.
      C = 0.4
      # α_cubic, the growth of W_est a round trip in segments, before W_est
      # reaches the window before the last reduction.
      ALPHA = 3 * (1 - BETA) / (1 + BETA)
      # The most target goes above the window, as a factor of it.
      MAX_TARGET_FACTOR = 1.5

      def self.requires_rate_sample? = false

      # :slow_start, :recovery, :application_limited, :reno_friendly,
      # :concave or :convex.
      attr_reader :state

      # `config` gives fast_convergence and beta_ecn.
      def initialize(max_datagram_size:, initial_window:, config:, tracer: nil)
        @max_datagram_size = max_datagram_size
        @initial_window = initial_window
        @fast_convergence = config.fast_convergence
        @beta_ecn = config.beta_ecn
        @cwnd = initial_window.call(max_datagram_size).to_f
        @ssthresh = nil #: Float?
        @recovery_start = nil #: Float?
        @in_recovery = false
        @app_limited = false
        @initial = true
        # The congestion avoidance stage: when it began, the window then,
        # W_max and K, W_est and α_cubic, and the window before the last
        # reduction.
        @epoch_start = nil #: Float?
        @w_max = 0.0
        @k = 0.0
        @w_est = 0.0
        @alpha = ALPHA
        @cwnd_prior = nil #: Float?
        # Since when the connection has been application-limited, which
        # the time of the stage does not count.
        @app_limited_since = nil #: Float?
        # A stage after persistent congestion starts with K = 0 and W_max the
        # window then (RFC 9438 "Timeout").
        @after_timeout = false
        @state = :slow_start
        @tracer = tracer
        # The smoothed RTT once there is an RTT sample, which pacing waits
        # for.
        @smoothed_rtt = nil #: Float?
      end

      def window = @cwnd.to_i

      def minimum_window = 2 * @max_datagram_size

      def on_packet_sent(bytes:, now:) = nil

      def on_ack(acked_bytes:, largest_acked_sent_at:, latest_rtt:, smoothed_rtt:, min_rtt:, app_limited:, now:, rate_sample: nil)
        @smoothed_rtt = smoothed_rtt if min_rtt
        start = @recovery_start
        @in_recovery = false if start && largest_acked_sent_at > start
        @app_limited = app_limited
        pause_epoch(app_limited, now)
        unless @in_recovery || app_limited
          if slow_start?
            @cwnd += acked_bytes
          else
            avoid_congestion(acked_bytes, smoothed_rtt, now)
          end
          @initial = false
        end
        update_state(now)
      end

      def on_loss(lost_bytes:, largest_lost_sent_at:, persistent:, now:)
        congestion_event(largest_lost_sent_at, now, BETA)
        if persistent
          @cwnd = minimum_window.to_f
          @recovery_start = nil
          @in_recovery = false
          @epoch_start = nil
          @after_timeout = true
        end
        update_state(now)
      end

      def on_ecn_ce(largest_acked_sent_at:, now:)
        congestion_event(largest_acked_sent_at, now, @beta_ecn || BETA)
        update_state(now)
      end

      # The minimum window follows the size, and an initial window not yet
      # moved is worked out again (RFC 9002 "Initial and Minimum Congestion
      # Window").
      def on_mtu_updated(max_datagram_size:, now:)
        @max_datagram_size = max_datagram_size
        @cwnd = @initial_window.call(max_datagram_size).to_f if @initial
        @cwnd = [@cwnd, minimum_window.to_f].max
      end

      # Bytes a second (Pacing), nil until there is an RTT sample: the
      # initial window may go at once before then (RFC 9002 "Pacing").
      def pacing_rate = (rtt = @smoothed_rtt) && Pacing.rate(@cwnd, rtt, slow_start: slow_start?)

      def metrics
        metrics = { congestion_window: window } #: Hash[Symbol, Integer]
        ssthresh = @ssthresh
        metrics[:ssthresh] = ssthresh.to_i if ssthresh
        rate = pacing_rate
        # qlog has it in bits a second.
        metrics[:pacing_rate] = (rate * 8).to_i if rate
        metrics
      end

      private def slow_start?
        ssthresh = @ssthresh
        ssthresh.nil? || @cwnd < ssthresh
      end

      # The time of the stage stands still while application-limited: the
      # stage begins later by how long that lasted.
      private def pause_epoch(app_limited, now)
        if app_limited
          @app_limited_since ||= now
        elsif (since = @app_limited_since)
          @app_limited_since = nil
          epoch = @epoch_start
          @epoch_start = epoch + (now - since) if epoch
        end
      end

      # One ACK frame of `acked_bytes` in congestion avoidance (RFC 9438
      # "Reno-Friendly Region", "Concave Region", "Convex Region").
      private def avoid_congestion(acked_bytes, smoothed_rtt, now)
        start_epoch(now) unless @epoch_start
        epoch = @epoch_start || now
        t = now - epoch
        @w_est += @alpha * @max_datagram_size * acked_bytes / @cwnd
        prior = @cwnd_prior
        @alpha = 1.0 if prior && @w_est >= prior
        if w_cubic(t) < @w_est
          @cwnd = [@cwnd, @w_est].max
        else
          target = w_cubic(t + smoothed_rtt).clamp(@cwnd, MAX_TARGET_FACTOR * @cwnd)
          @cwnd += (target - @cwnd) * acked_bytes / @cwnd
        end
      end

      # A congestion avoidance stage begins: K from W_max and the window
      # now, and W_est from the window.
      private def start_epoch(now)
        @epoch_start = now
        if @after_timeout || @w_max <= @cwnd
          @after_timeout = false
          @w_max = @cwnd
          @k = 0.0
        else
          @k = Math.cbrt((@w_max - @cwnd) / (C * @max_datagram_size))
        end
        @w_est = @cwnd
      end

      private def w_cubic(t) = C * @max_datagram_size * (t - @k)**3 + @w_max

      # RFC 9002 appendix B "On New Congestion Event", with RFC 9438
      # "Multiplicative Decrease" and "Fast Convergence": nothing for a packet
      # sent before the current recovery period began.
      private def congestion_event(sent_at, now, beta)
        start = @recovery_start
        return if start && sent_at <= start
        @recovery_start = now
        @in_recovery = true
        @initial = false
        @w_max = @fast_convergence && @cwnd < @w_max ? @cwnd * (1 + beta) / 2 : @cwnd
        @cwnd_prior = @cwnd
        @ssthresh = @cwnd = [@cwnd * beta, minimum_window.to_f].max
        @epoch_start = nil
        @alpha = ALPHA
      end

      private def update_state(now)
        state = if @in_recovery then :recovery
          elsif @app_limited then :application_limited
          elsif slow_start? then :slow_start
          elsif @epoch_start && w_cubic(now - (@epoch_start || now)) < @w_est then :reno_friendly
          elsif @cwnd < @w_max then :concave
          else :convex
          end
        return if state == @state
        @tracer.congestion_state_updated(old: @state, new: state, now:) if @tracer # steep:ignore
        @state = state
      end
    end
  end
end
