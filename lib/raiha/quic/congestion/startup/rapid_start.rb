# frozen_string_literal: true

module Raiha::Next::QUIC
  module Congestion
    module Startup
      # Rapid Start (draft-kazuho-ccwg-rapid-start-02): the start of a
      # connection and its first recovery period, in place of the slow start
      # of the controller it wraps, which goes on once the period ends.
      #
      # While the path builds no queue, rtt_floor (the least latest RTT of
      # about the last min_rtt) no greater than queue_buildup_thresh, the
      # window grows by twice the bytes acknowledged, three times a round
      # trip; otherwise by the bytes acknowledged, as in slow start
      # (Increasing the Congestion Window); with no sample in about the last
      # min_rtt, as slow start. Pacing goes at three, two or, in the
      # recovery period, 1.25 times the window a smoothed RTT, but for the
      # first full flight after the first RTT sample, until the bytes sent
      # in flight since come to the window, which goes over a full RTT and
      # no faster than slow start's first, twice RFC 9002's initial window a
      # smoothed RTT (Full-RTT Pacing).
      #
      # Before the first RTT sample, as for 0-RTT, there is nothing to pace
      # over a full RTT with, and nothing is paced: the path lets no more
      # than RFC 9002's initial window go in flight then, however large the
      # Config's (Path#window).
      #
      # The first loss or ECN-CE starts the recovery period (Congestion
      # Handling): the window is multiplied by the silence factor, which
      # stops sending until the bytes in flight come under it, then lessened
      # by the ack factor of each byte acknowledged and the loss factor of
      # each byte lost, the bytes of the loss that started it among them,
      # all of the factors from the wrapped controller's beta (Reduction
      # Factors). It goes no lower than a third of beta times the window
      # before, beta times the initial window (the MAY) or the minimum
      # window. Once the period ends, with an ACK of a packet sent after it
      # began, Rapid Start is done? and hands over: the controller takes the
      # window, the BDP and queue it came to, the window over beta, when the
      # period began and the smoothed RTT, and that ACK. The ACK frame comes
      # whole, so that bytes of packets sent before the period began that
      # come in it go to the controller too and lessen nothing; with the
      # peer acknowledging every second packet while data flows, that is a
      # packet or so. A loss or ECN-CE of a packet sent after the period
      # began, or persistent congestion, hands over first and goes to the
      # controller. Done, everything goes to the controller, until the path
      # takes it back with handover.
      class RapidStart
        # The version of the draft this follows.
        DRAFT = "draft-kazuho-ccwg-rapid-start-02"
        # Reduction Factors.
        K = 2.0 / 3
        # queue_buildup_thresh's RECOMMENDED terms: seconds and a factor.
        QUEUE_BUILDUP_MARGIN = 0.004
        QUEUE_BUILDUP_FACTOR = 1.10
        # The pacing N of growth by three times a round trip.
        THREE_TIMES = 3.0

        # queue_buildup_thresh, seconds (Increasing the Congestion Window).
        def self.queue_buildup_threshold(min_rtt) = [min_rtt + QUEUE_BUILDUP_MARGIN, min_rtt * QUEUE_BUILDUP_FACTOR].min

        def initialize(cc, max_datagram_size:, initial_window:, tracer: nil)
          @cc = cc
          @max_datagram_size = max_datagram_size
          @initial_window = initial_window
          @tracer = tracer
          @cwnd = cc.window.to_f
          @initial = true
          @app_limited = false
          # :probing, :recovery or :done.
          @phase = :probing
          @recovery_start = nil #: Float?
          # The recovery period's beta, and how low it takes the window.
          @beta = 1.0
          @floor = 0.0
          @smoothed_rtt = nil #: Float?
          @min_rtt = nil #: Float?
          # The RTT samples of about the last min_rtt that no later one is
          # below, and when each came, for rtt_floor: the first is the least,
          # and asking for it, as pacing does for every datagram, costs
          # nothing.
          @floor_times = [] #: Array[Float]
          @floor_rtts = [] #: Array[Float]
          # Whether the first full flight after the first RTT sample is still
          # going, and the bytes it sent in flight so far.
          @first_flight = true
          @first_flight_sent = 0
          @state = :rapid_start
        end

        # Whether the first recovery period is over, or what came after it
        # was the controller's to take.
        def done? = @phase == :done

        # The controller Rapid Start wrapped, for the path to take back once
        # done?.
        def handover = @cc

        def window = done? ? @cc.window : @cwnd.to_i

        def minimum_window = @cc.minimum_window

        def on_packet_sent(bytes:, now:)
          if @first_flight && @smoothed_rtt
            @first_flight_sent += bytes
            @first_flight = false if @first_flight_sent >= @cwnd
          end
          @cc.on_packet_sent(bytes:, now:)
        end

        def on_ack(acked_bytes:, largest_acked_sent_at:, latest_rtt:, smoothed_rtt:, min_rtt:, app_limited:, now:, rate_sample: nil)
          unless done?
            take_rtt(latest_rtt, smoothed_rtt, min_rtt, now)
            @app_limited = app_limited
            start = @recovery_start
            hand_over(now) if start && largest_acked_sent_at > start
          end
          return @cc.on_ack(acked_bytes:, largest_acked_sent_at:, latest_rtt:, smoothed_rtt:, min_rtt:, app_limited:, now:, rate_sample:) if done?
          if @phase == :recovery
            reduce(ack_factor * acked_bytes)
          elsif !app_limited
            @cwnd += (three_times? ? 2 : 1) * acked_bytes
            @initial = false
          end
          update_state(now)
        end

        def on_loss(lost_bytes:, largest_lost_sent_at:, persistent:, now:)
          start = @recovery_start
          hand_over(now) if !done? && (persistent || (start && largest_lost_sent_at > start))
          return @cc.on_loss(lost_bytes:, largest_lost_sent_at:, persistent:, now:) if done?
          enter_recovery(@cc.beta(ecn: false), now) if @phase == :probing
          reduce(loss_factor * lost_bytes)
          update_state(now)
        end

        def on_ecn_ce(largest_acked_sent_at:, now:)
          start = @recovery_start
          hand_over(now) if !done? && start && largest_acked_sent_at > start
          return @cc.on_ecn_ce(largest_acked_sent_at:, now:) if done?
          enter_recovery(@cc.beta(ecn: true), now) if @phase == :probing
          update_state(now)
        end

        # The controller hears of it too, for when it takes over. An initial
        # window not yet moved is worked out again (RFC 9002 "Initial and
        # Minimum Congestion Window").
        def on_mtu_updated(max_datagram_size:, now:)
          @cc.on_mtu_updated(max_datagram_size:, now:)
          return if done?
          @max_datagram_size = max_datagram_size
          @cwnd = @initial_window.call(max_datagram_size).to_f if @initial
          @cwnd = [@cwnd, minimum_window.to_f].max
        end

        # Bytes a second, nil until there is an RTT sample.
        def pacing_rate
          return @cc.pacing_rate if done?
          rtt = @smoothed_rtt or return nil
          return nil unless rtt.positive?
          return Pacing::OTHERWISE * @cwnd / rtt if @phase == :recovery
          return [@cwnd, 2.0 * Config::DEFAULT_INITIAL_WINDOW.call(@max_datagram_size)].max / rtt if @first_flight
          (three_times? ? THREE_TIMES : Pacing::SLOW_START) * @cwnd / rtt
        end

        # :rapid_start, :recovery or :application_limited, the controller's
        # once done.
        def state = done? ? @cc.state : @state

        def metrics
          return @cc.metrics if done?
          metrics = { congestion_window: window } #: Hash[Symbol, Integer]
          rate = pacing_rate
          # qlog has it in bits a second.
          metrics[:pacing_rate] = (rate * 8).to_i if rate
          metrics
        end

        # Keeps the RTT samples of the last min_rtt, an ACK without one
        # letting the old ones go all the same.
        private def take_rtt(latest_rtt, smoothed_rtt, min_rtt, now)
          return unless min_rtt
          @smoothed_rtt = smoothed_rtt
          @min_rtt = min_rtt
          if latest_rtt
            while (last = @floor_rtts.last) && last >= latest_rtt
              @floor_times.pop
              @floor_rtts.pop
            end
            @floor_times << now
            @floor_rtts << latest_rtt
          end
          while (time = @floor_times.first) && time < now - min_rtt
            @floor_times.shift
            @floor_rtts.shift
          end
        end

        # Whether the path builds no queue: rtt_floor no greater than
        # queue_buildup_thresh.
        private def three_times?
          min_rtt = @min_rtt or return false
          floor = @floor_rtts.first or return false
          floor <= self.class.queue_buildup_threshold(min_rtt)
        end

        private def enter_recovery(beta, now)
          @phase = :recovery
          @initial = false
          @recovery_start = now
          @beta = beta
          @floor = [@cwnd * beta / 3, @initial_window.call(@max_datagram_size) * beta, minimum_window.to_f].max
          reduce(@cwnd * (1 - silence_factor))
        end

        private def silence_factor = @beta + K * (1 - @beta)

        private def ack_factor = K * (1 - @beta)

        # The silence factor, so that the window the period ends with is
        # beta times the bytes acknowledged, however many were lost.
        private def loss_factor = silence_factor

        # The minimum window as it is now, after an MTU update.
        private def reduce(bytes)
          @cwnd = [@cwnd - bytes, @floor, minimum_window.to_f].max
        end

        # The controller takes its state from where Rapid Start's left off,
        # and the tracer hears of the change from Rapid Start's.
        private def hand_over(now)
          full_bdp = @phase == :recovery ? @cwnd / @beta : @cwnd
          @phase = :done
          @cc.on_startup_exit(window: @cwnd.to_i, full_bdp:, recovery_start: @recovery_start, smoothed_rtt: @smoothed_rtt, now:)
          state = @cc.state
          @tracer.congestion_state_updated(old: @state, new: state, now:) if @tracer && state != @state # steep:ignore
        end

        private def update_state(now)
          state = if @phase == :recovery then :recovery
            elsif @app_limited then :application_limited
            else :rapid_start
            end
          return if state == @state
          @tracer.congestion_state_updated(old: @state, new: state, now:) if @tracer # steep:ignore
          @state = state
        end
      end
    end
  end
end
