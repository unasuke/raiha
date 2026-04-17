# frozen_string_literal: true

require "json"

module Raiha
  module Qlog
    # Base event class per draft-ietf-quic-qlog-main-schema-13.
    # Event names carry a namespace prefix ("quic:") per the schema.
    class Event
      NAMESPACE = "quic"

      attr_reader :time, :event_type, :data

      def initialize(event_type:, data: {})
        @time = Time.now
        @event_type = event_type
        @data = data
      end

      def to_h
        {
          time: (@time.to_f * 1000).to_i,
          name: "#{NAMESPACE}:#{@event_type}",
          data: @data
        }
      end

      def to_json(*args)
        to_h.to_json(*args)
      end
    end

    # draft-ietf-quic-qlog-quic-events-12 Section 4: Connectivity events
    module ConnectionEvents
      class ConnectionStarted < Event
        # RFC 9000 Section 4.2: uses local/remote TupleEndpointInfo.
        # We log connection IDs only; the transport is UDP but IP/port are not always known here.
        def initialize(src_cid:, dest_cid:)
          super(
            event_type: :connection_started,
            data: {
              local: { connection_ids: [src_cid.to_s] },
              remote: { connection_ids: [dest_cid.to_s] }
            }
          )
        end
      end

      class ConnectionStateUpdated < Event
        def initialize(old_state:, new_state:)
          super(
            event_type: :connection_state_updated,
            data: {
              old: old_state.to_s,
              new: new_state.to_s
            }
          )
        end
      end

      class ConnectionClosed < Event
        def initialize(owner:, trigger:, error_code: nil, reason: nil)
          super(
            event_type: :connection_closed,
            data: {
              owner: owner.to_s,
              trigger: trigger.to_s,
              error_code: error_code,
              reason: reason
            }.compact
          )
        end
      end

      class ConnectionIdUpdated < Event
        def initialize(owner:, old_id:, new_id:)
          super(
            event_type: :connection_id_updated,
            data: {
              owner: owner.to_s,
              old: old_id.to_s,
              new: new_id.to_s
            }
          )
        end
      end
    end

    # draft-ietf-quic-qlog-quic-events-12 Section 5: Transport events
    module TransportEvents
      class PacketSent < Event
        def initialize(packet_type:, packet_number:, frames: [])
          super(
            event_type: :packet_sent,
            data: {
              header: {
                packet_type: packet_type.to_s,
                packet_number: packet_number
              },
              frames: frames.map { |f| FrameSerializer.to_h(f) }
            }
          )
        end
      end

      class PacketReceived < Event
        def initialize(packet_type:, packet_number:, frames: [])
          super(
            event_type: :packet_received,
            data: {
              header: {
                packet_type: packet_type.to_s,
                packet_number: packet_number
              },
              frames: frames.map { |f| FrameSerializer.to_h(f) }
            }
          )
        end
      end

      class PacketDropped < Event
        def initialize(packet_type: nil, trigger: nil)
          super(
            event_type: :packet_dropped,
            data: {
              packet_type: packet_type&.to_s,
              trigger: trigger&.to_s
            }.compact
          )
        end
      end

      class ParametersSet < Event
        # draft-12 Section 5.3: parameters use the `initiator` field ("local" or "remote")
        def initialize(initiator:, parameters:)
          super(
            event_type: :parameters_set,
            data: {
              initiator: initiator.to_s,
              **parameters
            }
          )
        end
      end

      class StreamStateUpdated < Event
        def initialize(stream_id:, stream_type:, old_state: nil, new_state:)
          super(
            event_type: :stream_state_updated,
            data: {
              stream_id: stream_id,
              stream_type: stream_type.to_s,
              old: old_state&.to_s,
              new: new_state.to_s
            }.compact
          )
        end
      end
    end

    # draft-ietf-quic-qlog-quic-events-12 Section 6: Security events
    module SecurityEvents
      class KeyUpdated < Event
        def initialize(key_type:, generation: nil, trigger: nil)
          super(
            event_type: :key_updated,
            data: {
              key_type: key_type.to_s,
              generation: generation,
              trigger: trigger&.to_s
            }.compact
          )
        end
      end

      class KeyDiscarded < Event
        def initialize(key_type:, generation: nil, trigger: nil)
          super(
            event_type: :key_discarded,
            data: {
              key_type: key_type.to_s,
              generation: generation,
              trigger: trigger&.to_s
            }.compact
          )
        end
      end
    end

    # draft-ietf-quic-qlog-quic-events-12 Section 7: Recovery events
    module RecoveryEvents
      # Renamed from MetricsUpdated in the spec (quic:recovery_metrics_updated)
      class RecoveryMetricsUpdated < Event
        def initialize(min_rtt: nil, smoothed_rtt: nil, latest_rtt: nil, rtt_variance: nil,
                       pto_count: nil, congestion_window: nil, bytes_in_flight: nil,
                       ssthresh: nil, packets_in_flight: nil, pacing_rate: nil)
          super(
            event_type: :recovery_metrics_updated,
            data: {
              min_rtt: min_rtt,
              smoothed_rtt: smoothed_rtt,
              latest_rtt: latest_rtt,
              rtt_variance: rtt_variance,
              pto_count: pto_count,
              congestion_window: congestion_window,
              bytes_in_flight: bytes_in_flight,
              ssthresh: ssthresh,
              packets_in_flight: packets_in_flight,
              pacing_rate: pacing_rate
            }.compact
          )
        end
      end

      class CongestionStateUpdated < Event
        def initialize(old_state: nil, new_state:)
          super(
            event_type: :congestion_state_updated,
            data: {
              old: old_state&.to_s,
              new: new_state.to_s
            }.compact
          )
        end
      end

      class PacketLost < Event
        def initialize(packet_type:, packet_number:, trigger: nil)
          super(
            event_type: :packet_lost,
            data: {
              header: {
                packet_type: packet_type.to_s,
                packet_number: packet_number
              },
              trigger: trigger&.to_s
            }.compact
          )
        end
      end
    end

    # Converts QUIC frame objects to qlog-compatible hashes (draft-12).
    module FrameSerializer
      def self.to_h(frame)
        case frame
        when Quic::Wire::Frames::AckFrame
          data = {
            frame_type: "ack",
            ack_delay: frame.ack_delay,
            acked_ranges: compute_acked_ranges(frame)
          }.compact
          data
        when Quic::Wire::Frames::CryptoFrame
          {
            frame_type: "crypto",
            offset: frame.offset,
            raw: { length: frame.data&.bytesize }.compact
          }
        when Quic::Wire::Frames::StreamFrame
          {
            frame_type: "stream",
            stream_id: frame.stream_id,
            offset: frame.offset,
            fin: frame.fin || false,
            raw: { length: frame.data&.bytesize }.compact
          }
        when Quic::Wire::Frames::PaddingFrame
          { frame_type: "padding" }
        when Quic::Wire::Frames::PingFrame
          { frame_type: "ping" }
        when Quic::Wire::Frames::ConnectionCloseFrame
          {
            frame_type: "connection_close",
            error_code: frame.error_code,
            reason_phrase: frame.reason_phrase
          }.compact
        when Quic::Wire::Frames::MaxDataFrame
          { frame_type: "max_data", maximum: frame.maximum_data }
        when Quic::Wire::Frames::MaxStreamDataFrame
          { frame_type: "max_stream_data", stream_id: frame.stream_id, maximum: frame.maximum_stream_data }
        when Quic::Wire::Frames::MaxStreamsFrame
          { frame_type: "max_streams", maximum: frame.maximum_streams }
        when Quic::Wire::Frames::HandshakeDoneFrame
          { frame_type: "handshake_done" }
        when Quic::Wire::Frames::NewConnectionIdFrame
          { frame_type: "new_connection_id" }
        when Quic::Wire::Frames::RetireConnectionIdFrame
          { frame_type: "retire_connection_id" }
        else
          { frame_type: frame.class.name.split("::").last.gsub(/Frame$/, "").gsub(/([a-z])([A-Z])/, '\1_\2').downcase }
        end
      end

      # Convert raiha's (gap, ack_range_length) encoding to draft-12's absolute
      # [[from, to]] ranges per RFC 9000 Section 19.3.1 semantics.
      def self.compute_acked_ranges(frame)
        return nil unless frame.largest_acknowledged && frame.ack_ranges

        ranges = []
        smallest_of_previous = nil

        frame.ack_ranges.each_with_index do |r, i|
          largest_in_range = if i.zero?
            frame.largest_acknowledged
          else
            smallest_of_previous - r.gap - 2
          end
          smallest_in_range = largest_in_range - r.ack_range_length
          ranges << [smallest_in_range, largest_in_range]
          smallest_of_previous = smallest_in_range
        end

        ranges
      end
    end
  end
end
