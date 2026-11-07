# frozen_string_literal: true

module Raiha::Next::QUIC
  # The connection IDs this end issued for the peer to send to (RFC 9000
  # "Issuing Connection IDs"): the one of the handshake, sequence number 0,
  # and those NEW_CONNECTION_ID frames carry, which the Endpoint makes
  # (Endpoint::Issuer) with their stateless reset tokens and leads to the
  # connection. Once the handshake is confirmed, as many are issued as the
  # peer's active_connection_id_limit takes, MAX at most; Retire Prior To
  # is always 0, as this end never retires its own. A NEW_CONNECTION_ID
  # frame lost goes again as it was. With no issuer, or with zero-length
  # connection IDs, none is issued.
  class IssuedConnectionIDs
    # The most IDs this end keeps active, sequence number 0 among them.
    MAX = 4

    # An ID issued, with the NEW_CONNECTION_ID frame that carries it, which
    # the ID of the handshake has none of.
    Entry = Data.define(:sequence_number, :connection_id, :frame)

    # The ID of the handshake, `first`, of `connection`, and what makes
    # the others.
    def initialize(first, issuer:, connection:)
      @issuer = first.empty? ? nil : issuer
      @connection = connection
      @active = [Entry.new(sequence_number: 0, connection_id: first, frame: nil)]
      @next_sequence_number = 1
      # The NEW_CONNECTION_ID frames to go.
      @to_send = [] #: Array[Wire::Frame::NewConnectionID]
    end

    # Issues IDs until min(`limit`, MAX) are active; `limit` is the peer's
    # active_connection_id_limit.
    def issue(limit)
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

    # A NEW_CONNECTION_ID frame lost goes again, while its ID is active.
    def lost(duty)
      entry = @active.find { |each| each.sequence_number == duty.sequence_number }
      frame = entry&.frame or return
      @to_send << frame unless @to_send.include?(frame)
    end
  end
end
