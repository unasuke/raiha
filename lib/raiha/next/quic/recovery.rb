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
    # The ranges of packet numbers received kept a space, and so sent in an
    # ACK; past it the oldest is let go (loss recovery's design, "Limits").
    MAX_ACK_RANGES = 64
    # The packets of only ACKs kept after the last ack-eliciting one.
    MAX_NON_ACK_ELICITING_TAIL = 1000
    # The least RTT sample a Retry gives.
    MIN_RETRY_RTT = 0.005
    # The records declared lost kept a space, beside those older than three
    # PTOs, to tell spurious losses (loss recovery's design, "Limits").
    MAX_LOST_PACKETS = 64

    SPACES = { initial: :initial, handshake: :handshake, zero_rtt: :application_data, one_rtt: :application_data }.freeze #: Hash[Symbol, space]

    # The path packets are sent on now.
    attr_reader :path
    attr_reader :pto_count
    # The packets declared lost, and those of them acknowledged later.
    attr_reader :packets_lost
    attr_reader :packets_spuriously_lost
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
      @spaces.fetch(:application_data).max_ack_delay = config.max_ack_delay
      @pto_count = 0
      @packets_lost = 0
      @packets_spuriously_lost = 0
      @peer_max_ack_delay = 0.025
      @handshake_confirmed = false
      @handshake_acknowledged = false
      @handshake_keys = false
      @first_initial_sent_at = nil #: Float?
      @first_one_rtt_packet_number = nil #: Integer?
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

    # The Initial or Handshake keys are gone (RFC 9001 "Discarding Unused
    # Keys"): what was sent in that space is thrown away and taken out of
    # flight, told to neither the congestion controller nor the owners, and
    # the PTO starts over (RFC 9002 "Discarding Keys and Packet State").
    def discard_space(packet_type, now:)
      space = space_of(packet_type)
      raise ArgumentError, "Application Data is never discarded" if space.name == :application_data
      space.discard.each do |packet|
        next unless packet.in_flight && !packet.path.abandoned?
        packet.path.remove_in_flight(sent_bytes: packet.sent_bytes, ack_eliciting: packet.ack_eliciting)
      end
      @pto_count = 0
      set_loss_detection_timer(now)
    end

    # A client's Retry came at `now` (RFC 9002 "Handling Retry Packets",
    # loss recovery's design, "On a Retry"). What was sent in Initial
    # packets that elicited an ACK and every 0-RTT packet go back to their
    # owners as lost, to be sent again, without a word to the congestion
    # controller; the packet numbers go on. The path starts over, and unless
    # a PTO ran out the time from the first Initial to the Retry, 5 ms at
    # least, is its first RTT sample.
    def on_retry(now:)
      initial = @spaces.fetch(:initial).discard
      zero_rtt = @spaces.fetch(:application_data).discard
      first_sent_at = @first_initial_sent_at
      sample = first_sent_at if @pto_count.zero?
      @path.start_over
      if sample
        @path.rtt.update(latest_rtt: [now - sample, MIN_RETRY_RTT].max, ack_delay: 0.0, max_ack_delay: @peer_max_ack_delay,
          handshake_confirmed: false, now:)
      end
      @pto_count = 0
      set_loss_detection_timer(now)
      trace_metrics(now)
      Outcome.new(acked: Outcome::NO_PACKETS, lost: initial.select(&:ack_eliciting) + zero_rtt, probe: nil)
    end

    # The server rejected 0-RTT (RFC 9001 "Rejecting 0-RTT", loss recovery's
    # design, "On a rejected 0-RTT"). The 0-RTT packets are those of
    # Application Data below the first 1-RTT one, or all of them when no
    # 1-RTT packet went yet: thrown away and taken out of flight without a
    # word to the congestion controller or the owners, whose streams start
    # over by other means. An ACK of one of them from now on is
    # PROTOCOL_VIOLATION.
    def on_zero_rtt_rejected(now:)
      space = @spaces.fetch(:application_data)
      boundary = @first_one_rtt_packet_number || (space.largest_sent || -1) + 1
      space.reject_below(boundary).each do |packet|
        next unless packet.in_flight && !packet.path.abandoned?
        packet.path.remove_in_flight(sent_bytes: packet.sent_bytes, ack_eliciting: packet.ack_eliciting)
      end
      set_loss_detection_timer(now)
    end

    # When something is to be done next: the loss detection timer or an
    # ACK that must go.
    def next_timeout = [@loss_detection_timer, *@spaces.each_value.filter_map(&:ack_deadline)].compact.min

    # Runs out the loss detection timer at `now` if it is due (RFC 9002 "On
    # Timeout"). A loss time declares the packets lost; otherwise the PTO
    # asks for two probes in the space it ran out in, or one in a Handshake
    # or Initial packet when nothing is in flight to keep the server from
    # being stuck, and backs off; the path hears how many ran out in a row.
    def on_timeout(now:)
      timer = @loss_detection_timer
      return Outcome::NONE unless timer && now >= timer
      loss = loss_space
      pto = pto_space
      trace_timer(:expired, (loss || pto)&.name || (lone_probe_space unless ack_eliciting_in_flight?), nil, now)
      if loss
        lost = detect_lost(loss, now)
        on_lost(lost, now)
        set_loss_detection_timer(now)
        trace_metrics(now)
        return Outcome.new(acked: Outcome::NO_PACKETS, lost:, probe: nil)
      end
      probe =
        if ack_eliciting_in_flight?
          Probe.new(space: pto&.name || :initial, packets: 2)
        else
          Probe.new(space: lone_probe_space, packets: 1)
        end
      @pto_count += 1
      @path.probe_timed_out(@pto_count, now:)
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

    # The least number the next packet of `packet_type` will have, without
    # taking it.
    def upcoming_packet_number(packet_type) = space_of(packet_type).upcoming_packet_number

    # How many bytes the packet number of the packet of `packet_type`
    # numbered `packet_number` goes in, by what the peer has acknowledged
    # (RFC 9000 "Packet Number Encoding and Decoding").
    def packet_number_length(packet_type, packet_number)
      Wire::PacketNumber.length(packet_number, largest_acked: space_of(packet_type).largest_acked_packet)
    end

    # The oldest packet in flight in `space` that elicits an ACK, nil when
    # none: what a probe carries again when nothing new waits (loss
    # recovery's design, "Probes"). It stays recorded as it is.
    def oldest_ack_eliciting(space) = @spaces.fetch(space).oldest_ack_eliciting

    # The largest packet number received in the space of `packet_type`, nil
    # before any, which the packet number of the next is decoded against.
    def largest_received(packet_type) = space_of(packet_type).largest_received

    # The connection moved to `path`: PTOs and loss detection go by its
    # RTT from now on, and the timer is set again by it.
    def switch_path(path, now:)
      @path = path
      set_loss_detection_timer(now)
    end

    # Records a packet sent at `now` on `path`, the current one unless
    # told, and counts it on the path when it is in flight.
    def on_packet_sent(packet_type:, packet_number:, sent_bytes:, ack_eliciting:, in_flight:, duties:, now:, pmtu_probe: false, path: @path)
      ecn = path.ecn
      packet = SentPacket.new(packet_number:, time_sent: now, sent_bytes:, ack_eliciting:, in_flight:, path:,
        duties: duties.frozen? ? duties : duties.dup.freeze, pmtu_probe:, ecn:)
      space_of(packet_type).add(packet)
      @first_initial_sent_at ||= now if packet_type == :initial
      @first_one_rtt_packet_number ||= packet_number if packet_type == :one_rtt
      path.ecn_sent if ecn == :ect0
      if in_flight
        path.add_in_flight(sent_bytes:, ack_eliciting:, now:)
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
      largest_before = space.largest_acked_packet
      acked = space.acknowledge(ack.ranges, frame_type: ack.ecn ? 0x03 : 0x02)
      spurious = take_spurious(space, ack.ranges, now)
      mtu_probes_acked(spurious, now)
      if acked.empty?
        return spurious.empty? ? Outcome::NONE : Outcome.new(acked: spurious, lost: Outcome::NO_PACKETS, probe: nil)
      end
      @handshake_acknowledged = true if space.name == :handshake
      sampled = take_rtt_sample(space, ack, acked, received_at)
      process_ecn(space, ack, acked, now) if largest_before.nil? || ack.largest > largest_before
      lost = detect_lost(space, now)
      on_lost(lost, now)
      on_acked(space, acked, sampled, now)
      @pto_count = 0 if peer_completed_address_validation?
      space.forget_lost(before: now - 3 * @path.rtt.pto_period)
      set_loss_detection_timer(now)
      trace_metrics(now)
      Outcome.new(acked: spurious.empty? ? acked : acked + spurious, lost:, probe: nil)
    end

    # Records a packet of `packet_type` received with the ECN mark of its
    # datagram, once its protection is off; false for a duplicate, which
    # the caller drops (RFC 9000 "Packet Number Spaces"). An ack-eliciting
    # one owes an ACK, at once or within max_ack_delay (loss recovery's
    # design, "When to send an ACK"). `received_at` is when the packet
    # arrived, earlier than `now` for one kept until its keys came.
    def on_packet_received(packet_type:, packet_number:, ecn:, ack_eliciting:, now:, received_at: now)
      space = space_of(packet_type)
      before = space.ack_deadline
      received = space.receive(packet_number, ecn:, ack_eliciting:, now: received_at)
      deadline = space.ack_deadline
      if deadline && deadline != before && @tracer
        @tracer.timer_updated(timer_type: :ack, event_type: :set, space: space.name, delta: [deadline - now, 0.0].max, now:) # steep:ignore
      end
      received
    end

    # Whether an ACK must go now in `space` (:initial, :handshake or
    # :application_data).
    def ack_due?(space, now:)
      deadline = @spaces.fetch(space).ack_deadline
      !deadline.nil? && now >= deadline
    end

    # Whether an ack-eliciting packet waits for an ACK in `space`, which can
    # then ride along with anything sent there.
    def ack_owed?(space) = @spaces.fetch(space).ack_owed?

    # The ACK frame to send in `space` now, nil before anything came.
    def ack_frame(space, now:) = @spaces.fetch(space).ack_frame(now:)

    # An ACK frame of `space` went out.
    def on_ack_sent(space, now:)
      space = @spaces.fetch(space)
      if space.ack_deadline && @tracer
        @tracer.timer_updated(timer_type: :ack, event_type: :cancelled, space: space.name, delta: nil, now:) # steep:ignore
      end
      space.ack_sent
    end

    # Whether a packet of only an ACK of `space` should carry a PING too:
    # with packets of only ACKs going one after another and nothing
    # ack-eliciting sent for a round trip, the peer would never acknowledge
    # the ACKs and what they acknowledge would never be let go (RFC 9000
    # "Limiting Ranges by Tracking ACK Frames"). The first after an
    # ack-eliciting packet goes alone, or two ends with nothing else to send
    # would answer each other's PING with one of their own.
    def ping_with_ack?(space, now:)
      space = @spaces.fetch(space)
      return false unless space.acks_alone?
      sent_at = space.time_of_last_ack_eliciting_packet
      sent_at.nil? || now - sent_at >= @path.rtt.smoothed_rtt
    end

    # A packet that carried an ACK frame of this end with the largest
    # `largest` was acknowledged (the duty Duty::Ack): what the frame
    # acknowledged need not be acknowledged again.
    def ack_frame_acknowledged(space, largest:) = @spaces.fetch(space).acknowledged_up_to(largest)

    # Whether the peer has validated this end's address, so that nothing is
    # owed to keep it from being stuck at its amplification limit (RFC 9002
    # "Handshakes and New Paths"): always for a server, and for a client once
    # a Handshake packet is acknowledged or the handshake confirmed.
    def peer_completed_address_validation? = @role == :server || @handshake_acknowledged || @handshake_confirmed

    private def space_of(packet_type) = @spaces.fetch(SPACES.fetch(packet_type))

    # A Hash#any? block of two parameters takes the key and value without
    # an Array for the pair.
    private def ack_eliciting_in_flight? = @spaces.any? { |_name, space| space.ack_eliciting_in_flight.positive? }

    # The space the block gives the earliest time for, nil when it gives
    # none; the first of those that tie. The loss detection timer is set
    # again on every packet sent and every ACK, so the spaces are walked
    # with a block and the earliest kept in locals: no Enumerator, Array or
    # record of a time.
    private def earliest_space
      earliest = nil #: PacketNumberSpace?
      earliest_time = Float::INFINITY
      @spaces.each_value do |space|
        time = yield(space)
        next unless time && time < earliest_time
        earliest = space
        earliest_time = time
      end
      earliest
    end

    # The space whose packets can be lost by time the earliest.
    private def loss_space = earliest_space(&:loss_time)

    # RFC 9002 "Computing PTO": the space with ack-eliciting packets in
    # flight whose PTO runs out the earliest, Application Data only once the
    # handshake is confirmed.
    private def pto_space = earliest_space { pto_time(_1) }

    # The PTO period of the current path, backed off by the PTO count.
    private def pto_duration = @path.rtt.pto_period * (1 << @pto_count)

    # When the PTO of `space` runs out: the PTO duration from its last
    # ack-eliciting packet, with the peer's max_ack_delay backed off for
    # Application Data. nil with none of them in flight, or for Application
    # Data before the handshake is confirmed.
    private def pto_time(space)
      sent_at = space.time_of_last_ack_eliciting_packet
      return nil unless space.ack_eliciting_in_flight.positive? && sent_at
      return sent_at + pto_duration unless space.name == :application_data
      sent_at + pto_duration + @peer_max_ack_delay * (1 << @pto_count) if @handshake_confirmed
    end

    # Where a probe goes with nothing in flight, to keep the server from
    # being stuck at its amplification limit.
    private def lone_probe_space = @handshake_keys ? :handshake : :initial

    # RFC 9002 "Setting the Loss Detection Timer": the earliest loss time;
    # else, unless the amplification limit leaves nothing to send, the
    # earliest PTO; else, with nothing in flight and the address not yet
    # validated by the peer, a PTO from now.
    private def set_loss_detection_timer(now)
      loss = loss_space
      pto = pto_space unless loss || @amplification_limited
      before = @loss_detection_timer
      timer = @loss_detection_timer =
        if loss then loss.loss_time
        elsif @amplification_limited then nil
        elsif pto then pto_time(pto)
        elsif ack_eliciting_in_flight? || peer_completed_address_validation? then nil
        else now + pto_duration
        end
      if timer
        trace_timer(:set, (loss || pto)&.name || lone_probe_space, timer - now, now) unless timer == before
      elsif before
        trace_timer(:cancelled, nil, nil, now)
      end
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

    # The records declared lost that an ACK acknowledges after all: counted
    # as spurious losses and handed back as acknowledged, and nothing to
    # the congestion controller, the RTT or the ECN counts (loss recovery's
    # design, "Acknowledged after all").
    private def take_spurious(space, ranges, now)
      spurious = space.take_spurious(ranges)
      @packets_spuriously_lost += spurious.size
      if @tracer
        spurious.each { |packet| @tracer.spurious_loss(packet_number: packet.packet_number, space: space.name, now:) } # steep:ignore
      end
      spurious
    end

    # Checks the ECN counts of an ACK that raised the largest acknowledged
    # (RFC 9000 "ECN Validation", loss recovery's design, "Validating the
    # counts"), for the path that sent the largest newly acknowledged
    # packet: the counts must be there when ECT(0) packets are newly
    # acknowledged, never go down, show no ECT(1), not exceed the ECT(0)
    # packets sent, and grow by as many ECT(0) and CE marks as ECT(0)
    # packets are newly acknowledged. A path that fails stops marking and
    # heeding counts. CE marks that grew tell its congestion controller
    # once.
    private def process_ecn(space, ack, acked, now)
      largest = acked.fetch(-1)
      path = largest.path
      return if path.abandoned? || path.ecn_state == :failed
      newly = acked.count { |packet| packet.ecn == :ect0 }
      counts = ack.ecn
      unless counts
        path.ecn_failed(now:) if newly.positive?
        return
      end
      last = space.ecn_counts
      if counts.ect1.positive? || counts.ect0 < last.ect0 || counts.ce < last.ce || counts.ect0 > space.ect0_sent ||
          (counts.ect0 - last.ect0) + (counts.ce - last.ce) < newly
        path.ecn_failed(now:)
        return
      end
      space.ecn_counts = counts
      path.ecn_validated(now:) if newly.positive?
      path.congestion.on_ecn_ce(largest_acked_sent_at: largest.time_sent, now:) if counts.ce > last.ce
    end

    # Each path that sent packets lost takes them out of flight and tells
    # its congestion controller once, with the latest time one of them was
    # sent (RFC 9002 "On Packets Lost"); persistent congestion takes its
    # minimum RTT anew, and tells the path, which may have lost its larger
    # datagrams in a black hole. The loss of a probe of the path MTU tells
    # the controller nothing, and goes to the path's search; a path
    # abandoned does neither.
    private def on_lost(lost, now)
      @packets_lost += lost.size
      lost.each { |packet| packet.path.mtu_probe_lost(packet.sent_bytes, now:) if packet.pmtu_probe && !packet.path.abandoned? }
      lost.select { |packet| packet.ecn == :ect0 }.group_by(&:path).each { |path, packets| path.ecn_lost(packets.size, now:) }
      lost.select(&:in_flight).group_by(&:path).each do |path, packets|
        next if path.abandoned?
        packets.each { |packet| path.remove_in_flight(sent_bytes: packet.sent_bytes, ack_eliciting: packet.ack_eliciting) }
        congested = packets.reject(&:pmtu_probe)
        largest_lost_sent_at = congested.map(&:time_sent).max or next
        persistent = persistent_congestion?(path, lost)
        path.congestion.on_loss(lost_bytes: congested.sum(&:sent_bytes), largest_lost_sent_at:, persistent:, now:)
        next unless persistent
        path.rtt.reset_min_rtt
        path.persistent_congestion(now:)
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
    # Acknowledgment"), and its rate meter those of Application Data; a
    # path abandoned does none of it.
    private def on_acked(space, acked, sampled, now)
      acked.select(&:in_flight).group_by(&:path).each do |path, packets|
        next if path.abandoned?
        packets.each { |packet| path.remove_in_flight(sent_bytes: packet.sent_bytes, ack_eliciting: packet.ack_eliciting) }
        acked_bytes = packets.sum(&:sent_bytes)
        path.delivered(acked_bytes, largest: packets.fetch(-1).packet_number, now:) if space.name == :application_data
        path.acked(acked_bytes:, largest_acked_sent_at: packets.map(&:time_sent).max || now, sampled: path.equal?(sampled), now:)
      end
      mtu_probes_acked(acked, now)
    end

    # The probes of the path MTU among `packets`, acknowledged, go to the
    # search of the path that sent them, those declared lost before too;
    # a probe is the one packet of its datagram, and its size the
    # datagram's.
    private def mtu_probes_acked(packets, now)
      packets.each { |packet| packet.path.mtu_probe_acked(packet.sent_bytes, now:) if packet.pmtu_probe && !packet.path.abandoned? }
    end

    # The values of the current path that changed since last told, at once
    # (loss recovery's design, "metrics_updated"); the delivery rate once
    # there is one, in bits a second as pacing_rate is.
    private def trace_metrics(now)
      return unless @tracer
      rtt = @path.rtt
      metrics = {
        latest_rtt: rtt.latest_rtt, smoothed_rtt: rtt.smoothed_rtt, min_rtt: rtt.min_rtt, rtt_variance: rtt.rttvar,
        pto_count: @pto_count, bytes_in_flight: @path.bytes_in_flight, packets_in_flight: @path.packets_in_flight,
        **@path.congestion.metrics
      } #: Hash[Symbol, metric]
      rate = @path.delivery_rate
      metrics[:delivery_rate] = (rate * 8).to_i if rate
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
require_relative "recovery/rate_meter"
require_relative "recovery/duty"
require_relative "recovery/sent_packet"
require_relative "recovery/packet_number_space"
