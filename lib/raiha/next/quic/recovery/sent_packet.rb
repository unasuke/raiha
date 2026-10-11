# frozen_string_literal: true

module Raiha::Next::QUIC
  class Recovery
    # A packet sent and not yet acknowledged, named as RFC 9002 "Sent Packet
    # Fields" names them. `sent_bytes` counts the QUIC header and frames, not
    # UDP or IP; `in_flight` is false for a packet of only ACK and
    # CONNECTION_CLOSE frames; `path` is the Path it went on, `duties` what
    # its owners hear of when it is acknowledged or lost, `pmtu_probe`
    # whether it probed the path MTU, whose loss does not tell the congestion
    # controller anything, and `ecn` the codepoint it carried (:not_ect or
    # :ect0).
    class SentPacket < Data.define(:packet_number, :time_sent, :sent_bytes, :ack_eliciting, :in_flight, :path, :duties, :pmtu_probe, :ecn)
    end
  end
end
