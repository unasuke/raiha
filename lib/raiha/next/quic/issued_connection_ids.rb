# frozen_string_literal: true

module Raiha::Next::QUIC
  # The connection IDs this end issued for the peer to send to (RFC 9000
  # "Issuing Connection IDs"): the one of the handshake, sequence number 0,
  # that of a server's preferred address, sequence number 1, and those
  # NEW_CONNECTION_ID frames carry, which the Endpoint makes
  # (Endpoint::Issuer) with their stateless reset tokens and leads to the
  # connection. Once the handshake is confirmed, as many are issued as the
  # peer's active_connection_id_limit takes, MAX at most; Retire Prior To
  # is always 0, as this end never retires its own. A NEW_CONNECTION_ID
  # frame lost goes again as it was. With no issuer, or with zero-length
  # connection IDs, none is issued.
  #
  # The peer retires IDs with RETIRE_CONNECTION_ID frames, and each ID it
  # retires is replaced by a new one. An ID retired still leads to the
  # connection until the time the connection gives, three PTOs on, so
  # that packets late on the way get there; then the Endpoint forgets it.
  # MAX_RETIRED wait at most, the oldest forgotten at once past them, so
  # that a peer that retires each new ID straight away, with a PTO it
  # makes long, piles up nothing (CVE-2024-1410). Whether a sequence
  # number was issued goes by the highest issued, and no set of those
  # retired is kept.
  class IssuedConnectionIDs
    # The most IDs this end keeps active, sequence number 0 among them:
    # enough that a server, which moves on a NAT rebinding only with an ID
    # to validate the path left with, follows a few rebindings in a row.
    MAX = 8
    # The most IDs retired that wait to be forgotten.
    MAX_RETIRED = 2 * MAX
    FRAME_TYPE = Wire::Frame::RetireConnectionID::TYPES.fetch(0)

    # An ID issued, with the NEW_CONNECTION_ID frame that carries it, which
    # the ID of the handshake has none of.
    Entry = Data.define(:sequence_number, :connection_id, :frame)

    # An ID retired, and when the Endpoint forgets it.
    Retired = Data.define(:connection_id, :forget_at)

    # The ID of the handshake, `first`, of `connection`, and what makes
    # the others.
    def initialize(first, issuer:, connection:)
      @issuer = first.empty? ? nil : issuer
      @connection = connection
      @active = [Entry.new(sequence_number: 0, connection_id: first, frame: nil)]
      @next_sequence_number = 1
      # The NEW_CONNECTION_ID frames to go.
      @to_send = [] #: Array[Wire::Frame::NewConnectionID]
      # The peer's active_connection_id_limit, once IDs are issued.
      @limit = 0
      # The IDs retired that wait to be forgotten, the oldest first.
      @retired = [] #: Array[Retired]
    end

    # The preferred address the transport parameters offer at `addresses`
    # (Config#preferred_address), with an ID issued for it, sequence number
    # 1, that no frame carries; nil with no addresses or no issuer, when
    # there is none.
    def preferred_address(addresses)
      return nil unless addresses && (issuer = @issuer)
      connection_id, stateless_reset_token = issuer.issue(@connection)
      @active << Entry.new(sequence_number: @next_sequence_number, connection_id:, frame: nil)
      @next_sequence_number += 1
      TransportParameters::PreferredAddress.new(ipv4: addresses[:ipv4], ipv6: addresses[:ipv6], connection_id:, stateless_reset_token:)
    end

    # Issues IDs until min(`limit`, MAX) are active; `limit` is the peer's
    # active_connection_id_limit.
    def issue(limit)
      @limit = limit
      issuer = @issuer or return
      while @active.size < [limit, MAX].min
        connection_id, stateless_reset_token = issuer.issue(@connection)
        frame = Wire::Frame::NewConnectionID.new(sequence_number: @next_sequence_number, retire_prior_to: 0, connection_id:,
          stateless_reset_token:)
        @active << Entry.new(sequence_number: @next_sequence_number, connection_id:, frame:)
        @to_send << frame
        @next_sequence_number += 1
      end
    end

    # The next NEW_CONNECTION_ID frame due and its duty, nil when none is
    # or it does not fit in `room` bytes.
    def next_frame(room)
      frame = @to_send.first or return nil
      return nil if Wire::Frame.encode([frame], ack_delay_exponent: 0).bytesize > room
      @to_send.shift
      [frame, Recovery::Duty::NewConnectionID.new(sequence_number: frame.sequence_number)]
    end

    # Takes a RETIRE_CONNECTION_ID frame that came in a packet to `dcid`
    # (RFC 9000 "RETIRE_CONNECTION_ID Frames"): a sequence number never
    # issued, or that of the packet's own ID, is PROTOCOL_VIOLATION, the
    # latter so that the two ends do not retire and replace for ever
    # (CVE-2025-7054); one retired already is nothing. The ID retired is
    # forgotten at `forget_at`, and a new one replaces it.
    def retire(frame, dcid:, forget_at:)
      sequence_number = frame.sequence_number
      if sequence_number >= @next_sequence_number
        raise Violation.new("RETIRE_CONNECTION_ID of #{sequence_number}, which was never issued", frame_type: FRAME_TYPE)
      end
      entry = @active.find { |each| each.sequence_number == sequence_number } or return
      if entry.connection_id == dcid
        raise Violation.new("RETIRE_CONNECTION_ID of #{sequence_number}, the ID of the packet it came in", frame_type: FRAME_TYPE)
      end
      @active.delete(entry)
      issued = entry.frame
      @to_send.delete(issued) if issued
      @retired << Retired.new(connection_id: entry.connection_id, forget_at:)
      while @retired.size > MAX_RETIRED
        oldest = @retired.shift or break
        forget(oldest.connection_id)
      end
      issue(@limit)
    end

    # When the next ID retired is to be forgotten; nil when none waits.
    def next_timeout = @retired.first&.forget_at

    # The IDs retired whose time has come are forgotten.
    def handle_timeout(now)
      while (oldest = @retired.first) && oldest.forget_at <= now
        @retired.shift
        forget(oldest.connection_id)
      end
    end

    # A NEW_CONNECTION_ID frame lost goes again, while its ID is active.
    def lost(duty)
      entry = @active.find { |each| each.sequence_number == duty.sequence_number }
      frame = entry&.frame or return
      @to_send << frame unless @to_send.include?(frame)
    end

    private def forget(connection_id) = @issuer&.forget(connection_id)
  end
end
