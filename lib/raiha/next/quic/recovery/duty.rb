# frozen_string_literal: true

module Raiha::Next::QUIC
  class Recovery
    # What a packet carried that its owner must hear about when the packet
    # is acknowledged or lost: one kind for each frame whose information is
    # sent again when lost, or whose acknowledgment means something. Loss
    # recovery keeps them with the packet and hands them back without
    # looking inside; the information lost is sent again built anew from the
    # latest state, not as a copy of the frame (RFC 9000 "Retransmission of
    # Information"). PING, PADDING, CONNECTION_CLOSE, PATH_CHALLENGE,
    # PATH_RESPONSE and DATAGRAM leave no duty.
    module Duty
      # A range of a stream's data; the data stays in the send buffer.
      class Stream < Data.define(:stream_id, :offset, :length, :fin); end

      # A range of the crypto stream of a number space (:initial, :handshake
      # or :application_data), the one the packet was sent in.
      class Crypto < Data.define(:space, :offset, :length); end

      # An ACK frame of a number space and the largest packet number it
      # acknowledged.
      class Ack < Data.define(:space, :largest); end

      class ResetStream < Data.define(:stream_id); end

      class StopSending < Data.define(:stream_id); end

      # The value sent, since only the most recent value is sent again.
      class MaxData < Data.define(:maximum); end

      class MaxStreamData < Data.define(:stream_id, :maximum); end

      class MaxStreams < Data.define(:bidirectional, :maximum); end

      class DataBlocked < Data.define(:maximum); end

      class StreamDataBlocked < Data.define(:stream_id, :maximum); end

      class StreamsBlocked < Data.define(:bidirectional, :maximum); end

      class NewConnectionID < Data.define(:sequence_number); end

      class RetireConnectionID < Data.define(:sequence_number); end

      # A NEW_TOKEN frame; the connection keeps its one token.
      class NewToken < Data.define; end

      class HandshakeDone < Data.define; end

      # Every kind; the set is closed.
      ALL = [
        Stream, Crypto, Ack, ResetStream, StopSending, MaxData, MaxStreamData, MaxStreams,
        DataBlocked, StreamDataBlocked, StreamsBlocked, NewConnectionID, RetireConnectionID, NewToken, HandshakeDone
      ].freeze

      # Tells `to` of the duties of the packets acknowledged and lost in
      # `outcome`, the acknowledged first so that a range acknowledged is not
      # put back to be sent again. An acknowledgment or loss that means
      # nothing to the owner tells nothing.
      def self.dispatch(outcome, to:)
        outcome.acked.each { |packet| packet.duties.each { |duty| acked(duty, to) } }
        outcome.lost.each { |packet| packet.duties.each { |duty| lost(duty, to) } }
      end

      # Each kind has its branch and there is no else: a kind added without
      # one raises.
      private_class_method def self.acked(duty, owner)
        case duty
        in Stream then owner.stream_data_acked(duty)
        in Crypto then owner.crypto_data_acked(duty)
        in Ack then owner.ack_frame_acked(duty)
        in ResetStream then owner.reset_stream_acked(duty)
        in RetireConnectionID then owner.retire_connection_id_acked(duty)
        in StopSending | MaxData | MaxStreamData | MaxStreams | DataBlocked | StreamDataBlocked | StreamsBlocked |
           NewConnectionID | NewToken | HandshakeDone
          nil
        end
      end

      private_class_method def self.lost(duty, owner)
        case duty
        in Stream then owner.stream_data_lost(duty)
        in Crypto then owner.crypto_data_lost(duty)
        in Ack then nil
        in ResetStream then owner.reset_stream_lost(duty)
        in StopSending then owner.stop_sending_lost(duty)
        in MaxData then owner.max_data_lost(duty)
        in MaxStreamData then owner.max_stream_data_lost(duty)
        in MaxStreams then owner.max_streams_lost(duty)
        in DataBlocked then owner.data_blocked_lost(duty)
        in StreamDataBlocked then owner.stream_data_blocked_lost(duty)
        in StreamsBlocked then owner.streams_blocked_lost(duty)
        in NewConnectionID then owner.new_connection_id_lost(duty)
        in RetireConnectionID then owner.retire_connection_id_lost(duty)
        in NewToken then owner.new_token_lost(duty)
        in HandshakeDone then owner.handshake_done_lost
        end
      end
    end
  end
end
