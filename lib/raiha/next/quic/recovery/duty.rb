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

      # The path the token was sent on.
      class NewToken < Data.define(:path); end

      class HandshakeDone < Data.define; end

      # Every kind; the set is closed.
      ALL = [
        Stream, Crypto, Ack, ResetStream, StopSending, MaxData, MaxStreamData, MaxStreams,
        DataBlocked, StreamDataBlocked, StreamsBlocked, NewConnectionID, RetireConnectionID, NewToken, HandshakeDone
      ].freeze
    end
  end
end
