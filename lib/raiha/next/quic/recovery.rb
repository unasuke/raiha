# frozen_string_literal: true

module Raiha::Next::QUIC
  # Loss recovery (RFC 9002): what was sent in each packet number space,
  # what the peer acknowledged, what is lost and when to probe, and what to
  # acknowledge in turn. The RTT, the congestion controller and the bytes in
  # flight are each path's (Path); a packet counts on the path it was sent
  # on.
  #
  # It takes packets by their type and keeps them in three packet number
  # spaces: Initial, Handshake, and Application Data for 0-RTT and 1-RTT.
  class Recovery
    # kInitialRtt, the RTT before a sample (RFC 9002 "Initial RTT"). A
    # constant, and the RTT of an earlier connection is not used.
    INITIAL_RTT = 0.333
    # kGranularity, the timer granularity (RFC 9002 "Time Threshold").
    GRANULARITY = 0.001
    # kPacketThreshold and kTimeThreshold (RFC 9002 "Acknowledgment-Based
    # Detection"), fixed.
    PACKET_THRESHOLD = 3
    TIME_THRESHOLD = 9.0 / 8
    # kPersistentCongestionThreshold (RFC 9002 "Duration").
    PERSISTENT_CONGESTION_THRESHOLD = 3

    SPACES = { initial: :initial, handshake: :handshake, zero_rtt: :application_data, one_rtt: :application_data }.freeze #: Hash[Symbol, space]

    # The path packets are sent on now.
    attr_reader :path
    attr_reader :pto_count
    # The peer's max_ack_delay, 25 ms until its transport parameters say.
    attr_writer :peer_max_ack_delay

    # `random` gives the bytes the skips of packet numbers are drawn from.
    def initialize(config:, path:, random:, now:, tracer: nil)
      @config = config
      @path = path
      @random = random
      @tracer = tracer
      @spaces = { initial: PacketNumberSpace.new(:initial), handshake: PacketNumberSpace.new(:handshake),
                  application_data: PacketNumberSpace.new(:application_data) } #: Hash[space, PacketNumberSpace]
      @pto_count = 0
      @peer_max_ack_delay = 0.025
      @handshake_confirmed = false
      if tracer
        tracer.recovery_parameters_set(
          now:, reordering_threshold: PACKET_THRESHOLD, time_threshold: TIME_THRESHOLD, timer_granularity: GRANULARITY,
          initial_rtt: INITIAL_RTT, max_datagram_size: path.max_datagram_size, initial_congestion_window: path.congestion.window,
          minimum_congestion_window: path.congestion.minimum_window, persistent_congestion_threshold: PERSISTENT_CONGESTION_THRESHOLD
        )
      end
    end

    # The handshake is confirmed (RFC 9001 "Handshake Confirmed").
    def handshake_confirmed!
      @handshake_confirmed = true
    end

    def handshake_confirmed? = @handshake_confirmed

    # The number for the next packet of `packet_type` (:initial,
    # :handshake, :zero_rtt or :one_rtt). Once the handshake is confirmed,
    # an Application Data number is left out now and then (loss recovery's
    # design, "Packet number skipping").
    def next_packet_number(packet_type)
      space = space_of(packet_type)
      space.skip_after(skip_interval) if space.name == :application_data && @handshake_confirmed && !space.skipping?
      space.next_packet_number
    end

    # Records a packet sent at `now`, and counts it on the path when it is
    # in flight.
    def on_packet_sent(packet_type:, packet_number:, sent_bytes:, ack_eliciting:, in_flight:, duties:, now:, pmtu_probe: false)
      packet = SentPacket.new(packet_number:, time_sent: now, sent_bytes:, ack_eliciting:, in_flight:, path: @path,
        duties: duties.frozen? ? duties : duties.dup.freeze, pmtu_probe:, ecn: :not_ect)
      space_of(packet_type).add(packet)
      @path.add_in_flight(sent_bytes:, ack_eliciting:, now:) if in_flight
      packet
    end

    private def space_of(packet_type) = @spaces.fetch(SPACES.fetch(packet_type))

    # Packets to send before the next skip: twice the initial window, half
    # the congestion window and up to one and a half more, in datagrams.
    # Never less than twice the initial window, so skips never come close.
    private def skip_interval
      max_datagram_size = @path.max_datagram_size
      initial = @config.initial_window.call(max_datagram_size) / max_datagram_size
      window = @path.window_packets
      2 * initial + window / 2 + random_below(window * 3 / 2 + 1)
    end

    private def random_below(bound) = @random.bytes(4).unpack1("N") % bound
  end
end

require_relative "recovery/rtt_estimator"
require_relative "recovery/duty"
require_relative "recovery/sent_packet"
require_relative "recovery/packet_number_space"
