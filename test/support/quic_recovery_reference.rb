# RFC 9002 Appendix A, "Loss Recovery Pseudocode", written out in Ruby for
# the differential test of loss recovery. Each method keeps the name of its
# pseudocode in snake case, and the order of its lines. What the pseudocode
# leaves to the implementation comes in from outside: `now`, the role, the
# Handshake keys, the handshake confirmed and the amplification limit.
#
# Three things differ from the text, each marked where it is:
# - the ACK Delay of an Initial ACK counts for nothing, the MAY the
#   implementation under test takes;
# - a PTO asks for two probes, the upper bound of "one or two";
# - get_loss_time_and_space passes over a space with no loss time, and
#   detect_and_remove_lost_packets compares by the same sum as the loss time,
#   where the text would pick 0 as the earliest and could round so that a
#   packet is not lost at its own loss time.
#
# Each event gives a Result of what it did, by packet numbers.
class QUICRecoveryReference
  K_PACKET_THRESHOLD = 3
  K_TIME_THRESHOLD = 9.0 / 8
  K_GRANULARITY = 0.001
  K_INITIAL_RTT = 0.333
  SPACES = %i[initial handshake application_data].freeze
  INFINITE = Float::INFINITY

  SentPacket = Struct.new(:packet_number, :ack_eliciting, :in_flight, :sent_bytes, :time_sent)

  # The packets newly acknowledged and lost, and the probes asked for as
  # [space, count].
  Result = Struct.new(:acked, :lost, :probe)

  attr_reader :latest_rtt, :smoothed_rtt, :rttvar, :min_rtt, :pto_count, :loss_detection_timer

  def initialize(role:, max_ack_delay:)
    @role = role
    @max_ack_delay = max_ack_delay
    @has_handshake_keys = false
    @handshake_confirmed = false
    @has_received_handshake_ack = false
    @at_anti_amplification_limit = false
    # Initialization
    @loss_detection_timer = nil
    @pto_count = 0
    @latest_rtt = 0
    @smoothed_rtt = K_INITIAL_RTT
    @rttvar = K_INITIAL_RTT / 2
    @min_rtt = 0
    @first_rtt_sample = 0
    @largest_acked_packet = SPACES.to_h { [_1, INFINITE] }
    @time_of_last_ack_eliciting_packet = SPACES.to_h { [_1, 0] }
    @loss_time = SPACES.to_h { [_1, 0] }
    @sent_packets = SPACES.to_h { [_1, {}] }
  end

  def handshake_keys_installed! = @has_handshake_keys = true

  def handshake_confirmed! = @handshake_confirmed = true

  # The server sent up to its limit. The pseudocode reads the limit in the
  # set_loss_detection_timer of that send.
  def anti_amplification_limit_reached(now)
    @at_anti_amplification_limit = true
    set_loss_detection_timer(now)
  end

  # The RFC's SHOULD outside the pseudocode, once persistent congestion is
  # established.
  def reset_min_rtt = @min_rtt = @latest_rtt

  def on_packet_sent(packet_number, pn_space, ack_eliciting, in_flight, sent_bytes, now)
    @sent_packets[pn_space][packet_number] = SentPacket.new(packet_number, ack_eliciting, in_flight, sent_bytes, now)
    if in_flight
      @time_of_last_ack_eliciting_packet[pn_space] = now if ack_eliciting
      set_loss_detection_timer(now)
    end
  end

  # For a datagram that lifts the server's limit.
  def on_datagram_received(now)
    return Result.new([], [], nil) unless @at_anti_amplification_limit
    @at_anti_amplification_limit = false
    set_loss_detection_timer(now)
    return on_loss_detection_timeout(now) if @loss_detection_timer && @loss_detection_timer < now
    Result.new([], [], nil)
  end

  def includes_ack_eliciting(packets) = packets.any?(&:ack_eliciting)

  # `ranges` are those of the ACK frame, the largest first.
  def on_ack_received(ranges, ack_delay, pn_space, now)
    largest_acked = ranges.first.end
    @has_received_handshake_ack = true if pn_space == :handshake
    if @largest_acked_packet[pn_space] == INFINITE
      @largest_acked_packet[pn_space] = largest_acked
    else
      @largest_acked_packet[pn_space] = [@largest_acked_packet[pn_space], largest_acked].max
    end

    newly_acked_packets = detect_and_remove_acked_packets(ranges, pn_space)
    return Result.new([], [], nil) if newly_acked_packets.empty?

    if newly_acked_packets.last.packet_number == largest_acked && includes_ack_eliciting(newly_acked_packets)
      @latest_rtt = now - newly_acked_packets.last.time_sent
      # Differs: the ACK Delay of an Initial ACK counts for nothing.
      update_rtt(pn_space == :initial ? 0.0 : ack_delay, now)
    end

    # ECN and the congestion controller's on_packets_lost and
    # on_packets_acked are left out of the comparison.
    lost_packets = detect_and_remove_lost_packets(pn_space, now)
    @pto_count = 0 if peer_completed_address_validation?
    set_loss_detection_timer(now)
    Result.new(newly_acked_packets.map(&:packet_number), lost_packets.map(&:packet_number), nil)
  end

  def detect_and_remove_acked_packets(ranges, pn_space)
    sent = @sent_packets[pn_space]
    acked = sent.each_value.select { |packet| ranges.any? { |range| range.cover?(packet.packet_number) } }
    acked.each { |packet| sent.delete(packet.packet_number) }
    acked
  end

  def update_rtt(ack_delay, now)
    if @first_rtt_sample == 0
      @min_rtt = @latest_rtt
      @smoothed_rtt = @latest_rtt
      @rttvar = @latest_rtt / 2
      @first_rtt_sample = now
      return
    end

    @min_rtt = [@min_rtt, @latest_rtt].min
    ack_delay = [ack_delay, @max_ack_delay].min if @handshake_confirmed

    adjusted_rtt = @latest_rtt
    adjusted_rtt = @latest_rtt - ack_delay if @latest_rtt >= @min_rtt + ack_delay

    @rttvar = 3.0 / 4 * @rttvar + 1.0 / 4 * (@smoothed_rtt - adjusted_rtt).abs
    @smoothed_rtt = 7.0 / 8 * @smoothed_rtt + 1.0 / 8 * adjusted_rtt
  end

  def get_loss_time_and_space
    time = @loss_time[:initial]
    space = :initial
    %i[handshake application_data].each do |pn_space|
      # Differs: a space with no loss time is passed over.
      next if @loss_time[pn_space] == 0
      if time == 0 || @loss_time[pn_space] < time
        time = @loss_time[pn_space]
        space = pn_space
      end
    end
    [time, space]
  end

  def get_pto_time_and_space(now)
    duration = (@smoothed_rtt + [4 * @rttvar, K_GRANULARITY].max) * (2**@pto_count)
    unless ack_eliciting_in_flight?
      raise "the peer validated the address" if peer_completed_address_validation?
      return [now + duration, @has_handshake_keys ? :handshake : :initial]
    end
    pto_timeout = INFINITE
    pto_space = :initial
    SPACES.each do |space|
      next unless ack_eliciting_in_flight?(space)
      if space == :application_data
        return [pto_timeout, pto_space] unless @handshake_confirmed
        duration += @max_ack_delay * (2**@pto_count)
      end

      t = @time_of_last_ack_eliciting_packet[space] + duration
      if t < pto_timeout
        pto_timeout = t
        pto_space = space
      end
    end
    [pto_timeout, pto_space]
  end

  def peer_completed_address_validation?
    return true if @role == :server
    @has_received_handshake_ack || @handshake_confirmed
  end

  def set_loss_detection_timer(now)
    earliest_loss_time, = get_loss_time_and_space
    if earliest_loss_time != 0
      @loss_detection_timer = earliest_loss_time
      return
    end

    if @at_anti_amplification_limit
      @loss_detection_timer = nil
      return
    end

    if !ack_eliciting_in_flight? && peer_completed_address_validation?
      @loss_detection_timer = nil
      return
    end

    timeout, = get_pto_time_and_space(now)
    @loss_detection_timer = timeout
  end

  def on_loss_detection_timeout(now)
    earliest_loss_time, pn_space = get_loss_time_and_space
    if earliest_loss_time != 0
      lost_packets = detect_and_remove_lost_packets(pn_space, now)
      raise "nothing lost at the loss time" if lost_packets.empty?
      set_loss_detection_timer(now)
      return Result.new([], lost_packets.map(&:packet_number), nil)
    end

    if ack_eliciting_in_flight?
      _, pn_space = get_pto_time_and_space(now)
      # Differs: two probes, the upper bound of "one or two".
      probe = [pn_space, 2]
    else
      raise "the peer validated the address" if peer_completed_address_validation?
      probe = [@has_handshake_keys ? :handshake : :initial, 1]
    end

    @pto_count += 1
    set_loss_detection_timer(now)
    Result.new([], [], probe)
  end

  def detect_and_remove_lost_packets(pn_space, now)
    raise "nothing acknowledged" if @largest_acked_packet[pn_space] == INFINITE
    @loss_time[pn_space] = 0
    lost_packets = []
    loss_delay = K_TIME_THRESHOLD * [@latest_rtt, @smoothed_rtt].max
    loss_delay = [loss_delay, K_GRANULARITY].max

    @sent_packets[pn_space].each_value do |unacked|
      next if unacked.packet_number > @largest_acked_packet[pn_space]

      # Differs: by the same sum as the loss time, not `now - loss_delay`.
      if unacked.time_sent + loss_delay <= now || @largest_acked_packet[pn_space] >= unacked.packet_number + K_PACKET_THRESHOLD
        lost_packets << unacked
      elsif @loss_time[pn_space] == 0
        @loss_time[pn_space] = unacked.time_sent + loss_delay
      else
        @loss_time[pn_space] = [@loss_time[pn_space], unacked.time_sent + loss_delay].min
      end
    end
    lost_packets.each { |packet| @sent_packets[pn_space].delete(packet.packet_number) }
    lost_packets
  end

  def on_packet_number_space_discarded(pn_space, now)
    raise "Application Data" if pn_space == :application_data
    @sent_packets[pn_space].clear
    @time_of_last_ack_eliciting_packet[pn_space] = 0
    @loss_time[pn_space] = 0
    @pto_count = 0
    set_loss_detection_timer(now)
  end

  private def ack_eliciting_in_flight?(space = nil)
    (space ? [space] : SPACES).any? { |pn_space| @sent_packets[pn_space].each_value.any? { _1.ack_eliciting && _1.in_flight } }
  end
end
