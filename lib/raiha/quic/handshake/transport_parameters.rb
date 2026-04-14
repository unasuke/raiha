# frozen_string_literal: true

require_relative "../varint"
require_relative "../wire/buffer"

module Raiha::Quic
  module Handshake
    # RFC 9000 Section 18 - Transport Parameters
    class TransportParameters
      PARAM_IDS = {
        original_destination_connection_id: 0x00,
        max_idle_timeout: 0x01,
        stateless_reset_token: 0x02,
        max_udp_payload_size: 0x03,
        initial_max_data: 0x04,
        initial_max_stream_data_bidi_local: 0x05,
        initial_max_stream_data_bidi_remote: 0x06,
        initial_max_stream_data_uni: 0x07,
        initial_max_streams_bidi: 0x08,
        initial_max_streams_uni: 0x09,
        ack_delay_exponent: 0x0a,
        max_ack_delay: 0x0b,
        disable_active_migration: 0x0c,
        preferred_address: 0x0d,
        active_connection_id_limit: 0x0e,
        initial_source_connection_id: 0x0f,
        retry_source_connection_id: 0x10,
      }.freeze

      attr_accessor :original_destination_connection_id
      attr_accessor :max_idle_timeout
      attr_accessor :stateless_reset_token
      attr_accessor :max_udp_payload_size
      attr_accessor :initial_max_data
      attr_accessor :initial_max_stream_data_bidi_local
      attr_accessor :initial_max_stream_data_bidi_remote
      attr_accessor :initial_max_stream_data_uni
      attr_accessor :initial_max_streams_bidi
      attr_accessor :initial_max_streams_uni
      attr_accessor :ack_delay_exponent
      attr_accessor :max_ack_delay
      attr_accessor :disable_active_migration
      attr_accessor :preferred_address
      attr_accessor :active_connection_id_limit
      attr_accessor :initial_source_connection_id
      attr_accessor :retry_source_connection_id

      def initialize
        @max_idle_timeout = 30_000
        @max_udp_payload_size = 65527
        # Connection-level flow control window (1MB)
        @initial_max_data = 1_048_576
        # Per-stream flow control window (256KB)
        @initial_max_stream_data_bidi_local = 262_144
        @initial_max_stream_data_bidi_remote = 262_144
        @initial_max_stream_data_uni = 262_144
        # Maximum number of streams the peer can open concurrently
        @initial_max_streams_bidi = 100
        @initial_max_streams_uni = 100
        @ack_delay_exponent = 3
        @max_ack_delay = 25
        @disable_active_migration = false
        @active_connection_id_limit = 2
      end

      def serialize
        buf = Wire::Buffer.new

        serialize_varint_param(buf, :max_idle_timeout, @max_idle_timeout)
        serialize_varint_param(buf, :max_udp_payload_size, @max_udp_payload_size)
        serialize_varint_param(buf, :initial_max_data, @initial_max_data)
        serialize_varint_param(buf, :initial_max_stream_data_bidi_local, @initial_max_stream_data_bidi_local)
        serialize_varint_param(buf, :initial_max_stream_data_bidi_remote, @initial_max_stream_data_bidi_remote)
        serialize_varint_param(buf, :initial_max_stream_data_uni, @initial_max_stream_data_uni)
        serialize_varint_param(buf, :initial_max_streams_bidi, @initial_max_streams_bidi)
        serialize_varint_param(buf, :initial_max_streams_uni, @initial_max_streams_uni)
        serialize_varint_param(buf, :ack_delay_exponent, @ack_delay_exponent)
        serialize_varint_param(buf, :max_ack_delay, @max_ack_delay)
        serialize_varint_param(buf, :active_connection_id_limit, @active_connection_id_limit)

        if @disable_active_migration
          buf.write_varint(PARAM_IDS[:disable_active_migration])
          buf.write_varint(0)
        end

        serialize_bytes_param(buf, :original_destination_connection_id, @original_destination_connection_id)
        serialize_bytes_param(buf, :stateless_reset_token, @stateless_reset_token)
        serialize_bytes_param(buf, :initial_source_connection_id, @initial_source_connection_id)
        serialize_bytes_param(buf, :retry_source_connection_id, @retry_source_connection_id)

        buf.to_s
      end

      def self.deserialize(data)
        params = self.new
        buf = Wire::Buffer.new(data)

        until buf.eof?
          param_id = buf.read_varint
          param_length = buf.read_varint
          param_value = buf.read(param_length)

          case param_id
          when PARAM_IDS[:original_destination_connection_id]
            params.original_destination_connection_id = param_value
          when PARAM_IDS[:max_idle_timeout]
            params.max_idle_timeout = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:stateless_reset_token]
            params.stateless_reset_token = param_value
          when PARAM_IDS[:max_udp_payload_size]
            params.max_udp_payload_size = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:initial_max_data]
            params.initial_max_data = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:initial_max_stream_data_bidi_local]
            params.initial_max_stream_data_bidi_local = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:initial_max_stream_data_bidi_remote]
            params.initial_max_stream_data_bidi_remote = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:initial_max_stream_data_uni]
            params.initial_max_stream_data_uni = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:initial_max_streams_bidi]
            params.initial_max_streams_bidi = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:initial_max_streams_uni]
            params.initial_max_streams_uni = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:ack_delay_exponent]
            params.ack_delay_exponent = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:max_ack_delay]
            params.max_ack_delay = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:disable_active_migration]
            params.disable_active_migration = true
          when PARAM_IDS[:active_connection_id_limit]
            params.active_connection_id_limit = Varint.decode(StringIO.new(param_value))
          when PARAM_IDS[:initial_source_connection_id]
            params.initial_source_connection_id = param_value
          when PARAM_IDS[:retry_source_connection_id]
            params.retry_source_connection_id = param_value
          end
        end

        params
      end

      private def serialize_varint_param(buf, name, value)
        return if value.nil?

        encoded_value = Varint.encode(value)
        buf.write_varint(PARAM_IDS[name])
        buf.write_varint(encoded_value.bytesize)
        buf.write(encoded_value)
      end

      private def serialize_bytes_param(buf, name, value)
        return if value.nil?

        buf.write_varint(PARAM_IDS[name])
        buf.write_varint(value.bytesize)
        buf.write(value)
      end
    end
  end
end
