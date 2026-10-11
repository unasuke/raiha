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
    # The packets declared lost.
    attr_reader :packets_lost
    # The peer's max_ack_delay, 25 ms until its transport parameters say.
    attr_writer :peer_max_ack_delay

    # Ack-eliciting packets to send now in `space`, as the PTO ran out:
    # new data if there is any, else what the oldest unacknowledged packet
    # carried, else a PING (RFC 9002 "Sending Probe Packets"). They go out
    # past the congestion window and pacing, but not past the server's
    # amplification limit.
    class Probe < Data.define(:space, :packets); end

    # What an ACK or a timer leaves for the owners of the packets: the
    # records acknowledged first, then those lost, and a probe to send.
    class Outcome < Data.define(:acked, :lost, :probe)
      NO_PACKETS = [] #: Array[SentPacket]
      NO_PACKETS.freeze
      NONE = new(acked: NO_PACKETS, lost: NO_PACKETS, probe: nil)
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
      @packets_lost = 0
      @peer_max_ack_delay = 0.025
      @handshake_confirmed = false
      @handshake_acknowledged = false
      @handshake_keys = false
      @amplification_limited = false
      @loss_detection_timer = nil #: Float?
      @metrics = {} #: Hash[Symbol, metric]
      if tracer
        tracer.recovery_parameters_set(
          now:, reordering_threshold: PACKET_THRESHOLD, time_threshold: TIME_THRESHOLD, timer_granularity: GRANULARITY,
          initial_rtt: INITIAL_RTT, max_datagram_size: path.max_datagram_size, initial_congestion_window: path.congestion.window,
          minimum_congestion_window: path.congestion.minimum_window, persistent_congestion_threshold: PERSISTENT_CONGESTION_THRESHOLD
        )
      end
    end

    # When the loss detection timer runs out (RFC 9002 "Setting the Loss
    # Detection Timer"), nil when it is not set.
    attr_reader :loss_detection_timer

    # The handshake is confirmed (RFC 9001 "Handshake Confirmed"), which
    # lets the PTO count Application Data.
    def handshake_confirmed!(now:)
      @handshake_confirmed = true
      set_loss_detection_timer(now)
    end

    def handshake_confirmed? = @handshake_confirmed

    # This end has Handshake keys, so that a probe to avoid a deadlock goes
    # in a Handshake packet.
    def handshake_keys_installed!
      @handshake_keys = true
    end

    # A server that may send no more until the client's address is
    # validated sets no timer, since it could send nothing when it ran out;
    # once a datagram lifts the limit the timer is set again (RFC 9002
    # "Handling Anti-Amplification Limits").
    def amplification_limited(limited, now:)
      @amplification_limited = limited
      set_loss_detection_timer(now)
    end

    # When something is to be done next: the loss detection timer.
    def next_timeout = @loss_detection_timer

    # Runs out the loss detection timer at `now` if it is due (RFC 9002 "On
    # Timeout"). A loss time declares the packets lost; otherwise the PTO
    # asks for two probes in the space it ran out in, or one in a Handshake
    # or Initial packet when nothing is in flight to keep the server from
    # being stuck, and backs off.
    def on_timeout(now:)
      timer = @loss_detection_timer
      return Outcome::NONE unless timer && now >= timer
      loss = loss_deadline
      pto = pto_deadline(now)
      trace_timer(:expired, (loss || pto)&.space, nil, now)
      if loss
        lost = detect_lost(@spaces.fetch(loss.space), now)
        on_lost(lost, now)
        set_loss_detection_timer(now)
        trace_metrics(now)
        return Outcome.new(acked: Outcome::NO_PACKETS, lost:, probe: nil)
      end
      probe =
        if ack_eliciting_in_flight?
          Probe.new(space: pto&.space || :initial, packets: 2)
        else
          Probe.new(space: @handshake_keys ? :handshake : :initial, packets: 1)
        end
      @pto_count += 1
      set_loss_detection_timer(now)
      trace_metrics(now)
      Outcome.new(acked: Outcome::NO_PACKETS, lost: Outcome::NO_PACKETS, probe:)
    end

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
      if in_flight
        @path.add_in_flight(sent_bytes:, ack_eliciting:, now:)
        set_loss_detection_timer(now)
      end
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
      lost = detect_lost(space, now)
      on_lost(lost, now)
      on_acked(acked, sampled, now)
      @pto_count = 0 if peer_completed_address_validation?
      set_loss_detection_timer(now)
      trace_metrics(now)
      Outcome.new(acked:, lost:, probe: nil)
    end

    # Whether the peer has validated this end's address, so that nothing is
    # owed to keep it from being stuck at its amplification limit (RFC 9002
    # "Handshakes and New Paths"): always for a server, and for a client once
    # a Handshake packet is acknowledged or the handshake confirmed.
    def peer_completed_address_validation? = @role == :server || @handshake_acknowledged || @handshake_confirmed

    private def space_of(packet_type) = @spaces.fetch(SPACES.fetch(packet_type))

    private def ack_eliciting_in_flight? = @spaces.each_value.any? { |space| space.ack_eliciting_in_flight.positive? }

    # When the loss detection timer runs out, and in which space.
    class Deadline < Data.define(:time, :space); end

    # The earliest time a packet can be lost by time, and its space.
    private def loss_deadline
      @spaces.each_value.filter_map { |space| (time = space.loss_time) && Deadline.new(time:, space: space.name) }.min_by(&:time)
    end

    # RFC 9002 "Setting the Loss Detection Timer".
    private def set_loss_detection_timer(now)
      deadline =
        if (loss = loss_deadline) then loss
        elsif @amplification_limited then nil
        elsif !ack_eliciting_in_flight? && peer_completed_address_validation? then nil
        else pto_deadline(now)
        end
      before = @loss_detection_timer
      timer = @loss_detection_timer = deadline&.time
      if deadline && timer
        trace_timer(:set, deadline.space, timer - now, now) unless timer == before
      elsif before
        trace_timer(:cancelled, nil, nil, now)
      end
    end

    # RFC 9002 "Computing PTO": the earliest PTO of the spaces with
    # ack-eliciting packets in flight, Application Data only once the
    # handshake is confirmed and with the peer's max_ack_delay, by the RTT of
    # the current path and backed off by the PTO count. With nothing in
    # flight, a PTO from now. nil when none applies.
    private def pto_deadline(now)
      backoff = 1 << @pto_count
      duration = @path.rtt.pto_period * backoff
      return Deadline.new(time: now + duration, space: @handshake_keys ? :handshake : :initial) unless ack_eliciting_in_flight?
      @spaces.each_value.filter_map do |space|
        sent_at = space.time_of_last_ack_eliciting_packet
        next unless space.ack_eliciting_in_flight.positive? && sent_at
        if space.name == :application_data
          next unless @handshake_confirmed
          Deadline.new(time: sent_at + duration + @peer_max_ack_delay * backoff, space: space.name)
        else
          Deadline.new(time: sent_at + duration, space: space.name)
        end
      end.min_by(&:time)
    end

    private def trace_timer(event_type, space, delta, now)
      @tracer.timer_updated(timer_type: :loss_timeout, event_type:, space:, delta:, now:) if @tracer # steep:ignore
    end

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

    # The records of `space` lost by now, by the RTT of the current path
    # (loss recovery's design, "Which path's RTT"): 9/8 of the larger of the
    # latest and smoothed RTT, and no less than the granularity.
    private def detect_lost(space, now)
      rtt = @path.rtt
      loss_delay = [TIME_THRESHOLD * [rtt.latest_rtt, rtt.smoothed_rtt].max, GRANULARITY].max
      space.detect_lost(loss_delay:, now:) do |packet, trigger|
        if @tracer
          @tracer.packet_lost(packet_number: packet.packet_number, space: space.name, trigger:, mtu_probe: packet.pmtu_probe, now:) # steep:ignore
        end
      end
    end

    # Each path that sent packets lost takes them out of flight and tells
    # its congestion controller once, with the latest time one of them was
    # sent (RFC 9002 "On Packets Lost"). The loss of a probe of the path MTU
    # tells it nothing; a path abandoned does neither.
    private def on_lost(lost, now)
      @packets_lost += lost.size
      lost.select(&:in_flight).group_by(&:path).each do |path, packets|
        next if path.abandoned?
        packets.each { |packet| path.remove_in_flight(sent_bytes: packet.sent_bytes, ack_eliciting: packet.ack_eliciting) }
        congested = packets.reject(&:pmtu_probe)
        largest_lost_sent_at = congested.map(&:time_sent).max or next
        persistent = persistent_congestion?(path, lost)
        path.congestion.on_loss(lost_bytes: congested.sum(&:sent_bytes), largest_lost_sent_at:, persistent:, now:)
        path.rtt.reset_min_rtt if persistent
      end
    end

    # RFC 9002 "Establishing Persistent Congestion", within the losses of
    # one detection in one space (loss recovery's design, "Persistent
    # congestion"). The losses run on while the packet numbers follow each
    # other on `path`; a gap, a packet acknowledged, skipped or lost before,
    # or one of another path ends the run. Two ack-eliciting packets of a
    # run sent after the path's first RTT sample and further apart than
    # the period establish it; the period is three times the smoothed RTT,
    # four times its variation and the peer's max_ack_delay.
    private def persistent_congestion?(path, lost)
      rtt = path.rtt
      first_sample_at = rtt.first_sample_at or return false
      period = (rtt.smoothed_rtt + [4 * rtt.rttvar, GRANULARITY].max + @peer_max_ack_delay) * PERSISTENT_CONGESTION_THRESHOLD
      run_start = nil #: Float?
      previous = nil #: SentPacket?
      lost.each do |packet|
        follows = previous && packet.packet_number == previous.packet_number + 1 && previous.path.equal?(path) && packet.path.equal?(path)
        run_start = nil unless follows
        previous = packet
        next unless packet.path.equal?(path) && packet.ack_eliciting && packet.time_sent > first_sample_at
        start = run_start ||= packet.time_sent
        return true if packet.time_sent - start > period
      end
      false
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
