# frozen_string_literal: true

module Raiha::Next::QUIC
  # One path of a connection, with what loss recovery keeps for it: the RTT,
  # the congestion controller made from the Config, and the bytes and
  # ack-eliciting packets in flight on it. A new path starts them all over
  # (RFC 9000 "Connection Migration"); packets sent on a path that is gone
  # count for nothing.
  class Path
    attr_reader :rtt
    attr_reader :congestion
    attr_reader :bytes_in_flight
    attr_reader :ack_eliciting_in_flight
    attr_reader :packets_in_flight
    attr_reader :max_datagram_size

    def initialize(config:, max_datagram_size: config.initial_max_datagram_size, tracer: nil)
      @rtt = Recovery::RttEstimator.new
      @congestion = config.congestion_control.new(max_datagram_size:, initial_window: config.initial_window, tracer:)
      @max_datagram_size = max_datagram_size
      @bytes_in_flight = 0
      @ack_eliciting_in_flight = 0
      @packets_in_flight = 0
      @app_limited = false
      @abandoned = false
    end

    # Counts a packet that went in flight on this path, and tells the
    # congestion controller.
    def add_in_flight(sent_bytes:, ack_eliciting:, now:)
      @bytes_in_flight += sent_bytes
      @packets_in_flight += 1
      @ack_eliciting_in_flight += 1 if ack_eliciting
      @congestion.on_packet_sent(bytes: sent_bytes, now:)
    end

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
    # filled it, leaves the window used.
    def transmission_stopped(reason)
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
  end
end
