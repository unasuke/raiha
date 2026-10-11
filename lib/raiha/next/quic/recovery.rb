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

    # What an ACK or a timer leaves for the owners of the packets: the
    # records acknowledged first, then those lost.
    class Outcome < Data.define(:acked, :lost)
      NO_PACKETS = [] #: Array[SentPacket]
      NO_PACKETS.freeze
      NONE = new(acked: NO_PACKETS, lost: NO_PACKETS)
    end

    # `role` is :client or :server, and `random` gives the bytes the skips
    # of packet numbers are drawn from.
    def initialize(role:, config:, path:, random:, now:, tracer: nil)
      @role = role
      @config = config
      @path = path
      @random = random
      @tracer = tracer
      @spaces = { initial: PacketNumberSpace.new(:initial), handshake: PacketNumberSpace.new(:handshake),
                  application_data: PacketNumberSpace.new(:application_data) } #: Hash[space, PacketNumberSpace]
      @pto_count = 0
      @peer_max_ack_delay = 0.025
      @handshake_confirmed = false
      @handshake_acknowledged = false
      @metrics = {} #: Hash[Symbol, metric]
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

    # Takes an ACK frame that came in a packet of `packet_type` at `now`
    # (RFC 9002 "On Receiving an Acknowledgment"). `received_at` is when the
    # packet arrived, earlier than `now` for one kept until its keys came;
    # the RTT sample counts from it. An ACK of a packet never sent raises a
    # Violation.
    def on_ack_received(packet_type:, ack:, now:, received_at: now)
      space = space_of(packet_type)
      acked = space.acknowledge(ack.ranges, frame_type: ack.ecn ? 0x03 : 0x02)
      return Outcome::NONE if acked.empty?
      @handshake_acknowledged = true if space.name == :handshake
      sampled = take_rtt_sample(space, ack, acked, received_at)
      on_acked(acked, sampled, now)
      @pto_count = 0 if peer_completed_address_validation?
      trace_metrics(now)
      Outcome.new(acked:, lost: Outcome::NO_PACKETS)
    end

    # Whether the peer has validated this end's address, so that nothing is
    # owed to keep it from being stuck at its amplification limit (RFC 9002
    # "Handshakes and New Paths"): always for a server, and for a client once
    # a Handshake packet is acknowledged or the handshake confirmed.
    def peer_completed_address_validation? = @role == :server || @handshake_acknowledged || @handshake_confirmed

    private def space_of(packet_type) = @spaces.fetch(SPACES.fetch(packet_type))

    # RFC 9002 "Generating RTT Samples": when the largest acknowledged is
    # acknowledged for the first time and with an ack-eliciting packet. The
    # ACK Delay of an Initial ACK counts for nothing. The sample goes to the
    # path the largest was sent on, and is lost with an abandoned one; the
    # path is given back.
    private def take_rtt_sample(space, ack, acked, received_at)
      largest = acked.fetch(-1)
      return nil unless largest.packet_number == ack.largest && acked.any?(&:ack_eliciting)
      path = largest.path
      return nil if path.abandoned?
      path.rtt.update(latest_rtt: received_at - largest.time_sent, ack_delay: space.name == :initial ? 0.0 : ack.delay,
        max_ack_delay: @peer_max_ack_delay, handshake_confirmed: @handshake_confirmed, now: received_at)
      path
    end

    # Each path that sent packets acknowledged takes them out of flight and
    # tells its congestion controller once (RFC 9002 "On Packet
    # Acknowledgment"); a path abandoned does neither.
    private def on_acked(acked, sampled, now)
      acked.select(&:in_flight).group_by(&:path).each do |path, packets|
        next if path.abandoned?
        packets.each { |packet| path.remove_in_flight(sent_bytes: packet.sent_bytes, ack_eliciting: packet.ack_eliciting) }
        rtt = path.rtt
        path.congestion.on_ack(
          acked_bytes: packets.sum(&:sent_bytes), largest_acked_sent_at: packets.map(&:time_sent).max || now,
          latest_rtt: path.equal?(sampled) ? rtt.latest_rtt : nil, smoothed_rtt: rtt.smoothed_rtt, min_rtt: rtt.min_rtt,
          app_limited: path.app_limited?, now:
        )
      end
    end

    # The values of the current path that changed since last told, at once
    # (loss recovery's design, "metrics_updated").
    private def trace_metrics(now)
      return unless @tracer
      rtt = @path.rtt
      metrics = {
        latest_rtt: rtt.latest_rtt, smoothed_rtt: rtt.smoothed_rtt, min_rtt: rtt.min_rtt, rtt_variance: rtt.rttvar,
        pto_count: @pto_count, bytes_in_flight: @path.bytes_in_flight, packets_in_flight: @path.packets_in_flight,
        **@path.congestion.metrics
      } #: Hash[Symbol, metric]
      changed = metrics.reject { |name, value| @metrics[name] == value }
      return if changed.empty?
      @metrics = metrics
      @tracer.metrics_updated(now:, **changed) # steep:ignore
    end

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
