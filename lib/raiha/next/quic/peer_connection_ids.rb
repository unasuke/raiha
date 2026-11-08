# frozen_string_literal: true

module Raiha::Next::QUIC
  # The connection IDs the peer issued for this end to send to (RFC 9000
  # "Issuing Connection IDs" and "Consuming and Retiring Connection IDs"):
  # the one of the handshake, sequence number 0, and those NEW_CONNECTION_ID
  # frames bring, with their stateless reset tokens.
  #
  # Retire Prior To retires the IDs numbered below it, the one in use too,
  # which then gives way to the lowest still active, and each goes back in
  # a RETIRE_CONNECTION_ID frame until acknowledged; so does an ID that
  # comes numbered below it. More active IDs than this end's
  # active_connection_id_limit is CONNECTION_ID_LIMIT_ERROR, and so is
  # more than twice that waiting to be retired, as the peer could make
  # them pile up by not acknowledging them (CVE-2026-84784). An ID or a
  # sequence number that comes again with something else is
  # PROTOCOL_VIOLATION.
  #
  # Each path this end sends on has an ID of its own (RFC 9000 "Privacy
  # Implications of Connection Migration"): a path other than the one in
  # use claims an ID no path has sent with, and gives it back retired when
  # the path goes. Zero-length IDs are the same on every path.
  class PeerConnectionIDs
    FRAME_TYPE = Wire::Frame::NewConnectionID::TYPES.fetch(0)

    Entry = Data.define(:sequence_number, :connection_id, :stateless_reset_token)

    # The ID in use.
    attr_reader :current

    # The peer's first ID, sequence number 0, with the stateless reset token
    # its transport parameters gave, if any; `limit` is this end's
    # active_connection_id_limit.
    def initialize(connection_id, stateless_reset_token:, limit:)
      @limit = limit
      @active = [Entry.new(sequence_number: 0, connection_id:, stateless_reset_token:)]
      @current = connection_id
      @retire_prior_to = 0
      # The sequence numbers to retire, and those retired and not yet
      # acknowledged.
      @to_retire = [] #: Array[Integer]
      @retiring = [] #: Array[Integer]
      # The IDs paths other than the one in use claimed.
      @claimed = [] #: Array[String]
    end

    # The stateless reset tokens a datagram that no packet of the
    # connection opens is compared with: those of the IDs this end sends
    # with, not of those active and not yet used, nor of those retired
    # (RFC 9000 "Detecting a Stateless Reset").
    def reset_tokens = @active.select { |entry| in_use?(entry.connection_id) }.filter_map(&:stateless_reset_token)

    # An ID for a path to send with that no path has sent with, the lowest
    # first; nil when there is none. Zero-length IDs are always there.
    def claim
      return @current if @current.empty?
      entry = @active.find { |each| !in_use?(each.connection_id) } or return nil
      @claimed << entry.connection_id
      entry.connection_id
    end

    # The path that claimed `connection_id` is now the one in use: the ID
    # in use before is claimed by the path that leaves it.
    def switch(connection_id)
      return if connection_id == @current || !@claimed.delete(connection_id)
      @claimed << @current
      @current = connection_id
    end

    # A path that claimed `connection_id` went: the ID is retired, as no
    # other path sends with it.
    def release(connection_id)
      return unless @claimed.delete(connection_id)
      entry = @active.find { |each| each.connection_id == connection_id } or return
      @active.delete(entry)
      retire(entry.sequence_number)
    end

    # Takes a NEW_CONNECTION_ID frame.
    def receive(frame)
      raise Violation.new("NEW_CONNECTION_ID to an end that sends no connection ID", frame_type: FRAME_TYPE) if @current.empty?
      return if known?(frame)
      if frame.sequence_number < @retire_prior_to
        retire(frame.sequence_number)
      else
        @active << Entry.new(sequence_number: frame.sequence_number, connection_id: frame.connection_id,
          stateless_reset_token: frame.stateless_reset_token)
      end
      retire_prior_to(frame.retire_prior_to) if frame.retire_prior_to > @retire_prior_to
      if @active.size > @limit
        raise Violation.new("#{@active.size} connection IDs, over the limit of #{@limit}", code: ErrorCode::CONNECTION_ID_LIMIT_ERROR,
          frame_type: FRAME_TYPE)
      end
      return unless @to_retire.size + @retiring.size > 2 * @limit
      raise Violation.new("#{@to_retire.size + @retiring.size} connection IDs waiting to be retired", code: ErrorCode::CONNECTION_ID_LIMIT_ERROR,
        frame_type: FRAME_TYPE)
    end

    # The next RETIRE_CONNECTION_ID due and its duty, nil when none is or
    # it does not fit in `room` bytes.
    def next_frame(room)
      sequence_number = @to_retire.first or return nil
      frame = Wire::Frame::RetireConnectionID.new(sequence_number:)
      return nil if Wire::Frame.encode([frame], ack_delay_exponent: 0).bytesize > room
      @retiring << @to_retire.shift
      [frame, Recovery::Duty::RetireConnectionID.new(sequence_number:)]
    end

    def retire_acked(duty) = @retiring.delete(duty.sequence_number)

    # A lost RETIRE_CONNECTION_ID goes again.
    def retire_lost(duty)
      return unless @retiring.delete(duty.sequence_number)
      @to_retire << duty.sequence_number
    end

    # Whether the frame repeats an active ID; one that comes again with
    # another ID, sequence number or token is PROTOCOL_VIOLATION.
    private def known?(frame)
      entry = @active.find { |each| each.sequence_number == frame.sequence_number || each.connection_id == frame.connection_id }
      return false unless entry
      same = entry.sequence_number == frame.sequence_number && entry.connection_id == frame.connection_id &&
        entry.stateless_reset_token == frame.stateless_reset_token
      raise Violation.new("connection ID #{frame.sequence_number} again with something else", frame_type: FRAME_TYPE) unless same
      true
    end

    # The IDs numbered below `limit` are retired, and the one in use gives
    # way to the lowest still active.
    private def retire_prior_to(limit)
      @retire_prior_to = limit
      retired, @active = @active.partition { |entry| entry.sequence_number < limit }
      retired.each { |entry| retire(entry.sequence_number) }
      return if @active.any? { |entry| entry.connection_id == @current }
      @current = @active.min_by(&:sequence_number)&.connection_id || @current
    end

    private def in_use?(connection_id) = connection_id == @current || @claimed.include?(connection_id)

    private def retire(sequence_number)
      @to_retire << sequence_number unless @to_retire.include?(sequence_number) || @retiring.include?(sequence_number)
    end
  end
end
