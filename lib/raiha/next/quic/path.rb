# frozen_string_literal: true

module Raiha::Next::QUIC
  # One path of a connection, with what loss recovery keeps for it: the RTT,
  # the congestion controller made from the Config, the bytes and
  # ack-eliciting packets in flight on it, and its Pacer, whose bucket
  # holds RFC 9002's initial window whatever the Config's is, or what the
  # pacing rate gives in one granularity when that is more, and its
  # RateMeter. A new path starts them all over (RFC 9000 "Connection
  # Migration"); packets sent on a path that is gone count for nothing.
  class Path
    attr_reader :rtt
    attr_reader :congestion
    attr_reader :bytes_in_flight
    attr_reader :ack_eliciting_in_flight
    attr_reader :packets_in_flight
    attr_reader :max_datagram_size

    def initialize(config:, max_datagram_size: config.initial_max_datagram_size, tracer: nil)
      @config = config
      @max_datagram_size = max_datagram_size
      @tracer = tracer
      start_over
      @abandoned = false
      @ecn_state = :testing
      @ecn_testing_sent = 0
      @ecn_testing_lost = 0
    end

    # Takes the RTT, the congestion controller and the counts in flight back
    # to where a new path starts, as after a Retry (RFC 9002 "Handling Retry
    # Packets").
    def start_over
      @rtt = Recovery::RttEstimator.new
      @congestion = @config.congestion_control.new(max_datagram_size: @max_datagram_size, initial_window: @config.initial_window, config: @config,
        tracer: @tracer)
      @bytes_in_flight = 0
      @ack_eliciting_in_flight = 0
      @packets_in_flight = 0
      @app_limited = false
      @pacer = Pacer.new(capacity: Config::DEFAULT_INITIAL_WINDOW.call(@max_datagram_size), granularity: @config.pacing_granularity)
      @pacing_release_at = nil #: Float?
      @rate_meter = Recovery::RateMeter.new
    end

    # :testing, :capable or :failed (loss recovery's design, "Marking").
    attr_reader :ecn_state

    # The codepoint to mark packets with: ECT(0) until the path fails.
    def ecn = @ecn_state == :failed ? :not_ect : :ect0

    # A packet marked ECT(0) was sent.
    def ecn_sent
      @ecn_testing_sent += 1 if @ecn_state == :testing
    end

    # ECT(0) packets were declared lost: while testing, all of them lost
    # fails the path (RFC 9000 "ECN Validation").
    def ecn_lost(count, now:)
      return unless @ecn_state == :testing
      @ecn_testing_lost += count
      ecn_failed(now:) if @ecn_testing_lost >= @ecn_testing_sent
    end

    # An ACK of ECT(0) packets passed validation.
    def ecn_validated(now:)
      change_ecn_state(:capable, now) if @ecn_state == :testing
    end

    # The path fails ECN for good: no marks and no counts heeded.
    def ecn_failed(now:)
      change_ecn_state(:failed, now)
    end

    # Counts a packet that went in flight on this path, and tells the
    # congestion controller.
    def add_in_flight(sent_bytes:, ack_eliciting:, now:)
      @bytes_in_flight += sent_bytes
      @packets_in_flight += 1
      @ack_eliciting_in_flight += 1 if ack_eliciting
      @pacer.sent(sent_bytes)
      @congestion.on_packet_sent(bytes: sent_bytes, now:)
    end

    # Whether pacing lets a datagram of `size` bytes go in flight now, at
    # the congestion controller's rate; when it does not, `pacing_release_at`
    # is when it will.
    def paced?(size, now)
      @pacing_release_at = @pacer.release_at(size, @congestion.pacing_rate, now)
      @pacing_release_at.nil?
    end

    # When pacing lets what is held back go, while sending is stopped for
    # it.
    attr_reader :pacing_release_at

    # Bytes in flight of Application Data on this path were acknowledged at
    # `now`, the largest packet newly acknowledged numbered `largest`.
    def delivered(bytes, largest:, now:) = @rate_meter.on_ack(bytes, largest:, now:)

    # The rate the path delivers at by its RateMeter, bytes a second; nil
    # before a sample.
    def delivery_rate = @rate_meter.rate

    # No longer counts a packet acknowledged, lost or discarded.
    def remove_in_flight(sent_bytes:, ack_eliciting:)
      @bytes_in_flight -= sent_bytes
      @packets_in_flight -= 1
      @ack_eliciting_in_flight -= 1 if ack_eliciting
    end

    # Whether the window went unused when sending last stopped, which keeps
    # the congestion controller from growing it (RFC 9002 "Underutilizing
    # the Congestion Window"). false until the first stop.
    def app_limited? = @app_limited

    # Sending stopped, for `reason`: :drained (nothing left to send),
    # :flow_control, :amplification (the server's limit before the client's
    # address is validated), :congestion (the window is full) or :pacing.
    # Only the window filled up, or pacing holding back what would have
    # filled it, leaves the window used. With stream data or DATAGRAMs
    # `waiting` and the window or pacing holding them back, the rate meter
    # counts what goes from `next_packet_number`, the least the next 1-RTT
    # packet will be numbered.
    def transmission_stopped(reason, waiting:, next_packet_number:)
      @pacing_release_at = nil unless reason == :pacing
      @rate_meter.sending_stopped(limited: waiting && (reason == :congestion || reason == :pacing), next_packet_number:)
      @app_limited = case reason
        when :drained then @bytes_in_flight < @congestion.window
        when :flow_control, :amplification then true
        when :congestion, :pacing then false
        else raise ArgumentError, "unknown reason to stop sending: #{reason.inspect}"
        end
    end

    # The path's MTU changed (DPLPMTUD).
    def update_max_datagram_size(max_datagram_size, now:)
      @max_datagram_size = max_datagram_size
      @congestion.on_mtu_updated(max_datagram_size:, now:)
    end

    # The congestion window in datagrams.
    def window_packets = @congestion.window / @max_datagram_size

    # The connection left this path; what was sent on it no longer counts.
    def abandon = @abandoned = true

    def abandoned? = @abandoned

    private def change_ecn_state(state, now)
      return if state == @ecn_state
      @tracer.ecn_state_updated(old: @ecn_state, new: state, now:) if @tracer # steep:ignore
      @ecn_state = state
    end
  end
end
