# frozen_string_literal: true

require "json"

module Raiha
  module Qlog
    # Base event class per draft-ietf-quic-qlog-main-schema
    class Event
      attr_reader :time, :category, :event_type, :data

      def initialize(category:, event_type:, data: {})
        @time = Time.now
        @category = category
        @event_type = event_type
        @data = data
      end

      def to_h
        {
          time: (@time.to_f * 1000).to_i,
          name: "#{@category}:#{@event_type}",
          data: @data
        }
      end

      def to_json(*args)
        to_h.to_json(*args)
      end
    end

    # draft-ietf-quic-qlog-quic-events Section 4: Connectivity events
    module ConnectionEvents
      class ConnectionStarted < Event
        def initialize(src_cid:, dest_cid:)
          super(
            category: :connectivity,
            event_type: :connection_started,
            data: {
              src_cid: src_cid.to_s,
              dst_cid: dest_cid.to_s
            }
          )
        end
      end

      class ConnectionStateUpdated < Event
        def initialize(old_state:, new_state:)
          super(
            category: :connectivity,
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
            category: :connectivity,
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
            category: :connectivity,
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

    # draft-ietf-quic-qlog-quic-events Section 5: Transport events
    module TransportEvents
      class PacketSent < Event
        def initialize(packet_type:, packet_number:, frames: [])
          super(
            category: :transport,
            event_type: :packet_sent,
            data: {
              header: {
                packet_type: packet_type.to_s,
                packet_number: packet_number
              },
              frames: frames.map { |f| frame_to_h(f) }
            }
          )
        end

        private def frame_to_h(frame)
          FrameSerializer.to_h(frame)
        end
      end

      class PacketReceived < Event
        def initialize(packet_type:, packet_number:, frames: [])
          super(
            category: :transport,
            event_type: :packet_received,
            data: {
              header: {
                packet_type: packet_type.to_s,
                packet_number: packet_number
              },
              frames: frames.map { |f| frame_to_h(f) }
            }
          )
        end

        private def frame_to_h(frame)
          FrameSerializer.to_h(frame)
        end
      end

      class PacketDropped < Event
        def initialize(packet_type: nil, trigger: nil)
          super(
            category: :transport,
            event_type: :packet_dropped,
            data: {
              packet_type: packet_type&.to_s,
              trigger: trigger&.to_s
            }.compact
          )
        end
      end

      class ParametersSet < Event
        def initialize(owner:, parameters:)
          super(
            category: :transport,
            event_type: :parameters_set,
            data: {
              owner: owner.to_s,
              **parameters
            }
          )
        end
      end

      class StreamStateUpdated < Event
        def initialize(stream_id:, stream_type:, old_state: nil, new_state:)
          super(
            category: :transport,
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

    # draft-ietf-quic-qlog-quic-events Section 6: Security events
    module SecurityEvents
      class KeyUpdated < Event
        def initialize(key_type:, generation: nil, trigger: nil)
          super(
            category: :security,
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
            category: :security,
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

    # draft-ietf-quic-qlog-quic-events Section 7: Recovery events
    module RecoveryEvents
      class MetricsUpdated < Event
        def initialize(min_rtt: nil, smoothed_rtt: nil, latest_rtt: nil, rtt_variance: nil,
                       congestion_window: nil, bytes_in_flight: nil)
          super(
            category: :recovery,
            event_type: :metrics_updated,
            data: {
              min_rtt: min_rtt,
              smoothed_rtt: smoothed_rtt,
              latest_rtt: latest_rtt,
              rtt_variance: rtt_variance,
              congestion_window: congestion_window,
              bytes_in_flight: bytes_in_flight
            }.compact
          )
        end
      end

      class CongestionStateUpdated < Event
        def initialize(old_state: nil, new_state:)
          super(
            category: :recovery,
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
            category: :recovery,
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

    # Converts QUIC frame objects to qlog-compatible hashes
    module FrameSerializer
      def self.to_h(frame)
        case frame
        when Quic::Wire::Frames::AckFrame
          {
            frame_type: "ack",
            largest_acknowledged: frame.largest_acknowledged,
            ack_delay: frame.ack_delay,
            acked_ranges: frame.ack_ranges&.map { |r| [r.gap, r.ack_range_length] }
          }.compact
        when Quic::Wire::Frames::CryptoFrame
          {
            frame_type: "crypto",
            offset: frame.offset,
            length: frame.data&.bytesize
          }
        when Quic::Wire::Frames::StreamFrame
          {
            frame_type: "stream",
            stream_id: frame.stream_id,
            offset: frame.offset,
            length: frame.data&.bytesize,
            fin: frame.fin || false
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
          { frame_type: "max_data", maximum_data: frame.maximum_data }
        when Quic::Wire::Frames::MaxStreamDataFrame
          { frame_type: "max_stream_data", stream_id: frame.stream_id, maximum_stream_data: frame.maximum_stream_data }
        when Quic::Wire::Frames::MaxStreamsFrame
          { frame_type: "max_streams", maximum_streams: frame.maximum_streams }
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
    end
  end
end
