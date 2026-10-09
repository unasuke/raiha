# frozen_string_literal: true

module Raiha::Next::QUIC
  # The transport parameters of one end (RFC 9000 "Transport Parameter
  # Definitions", and max_datagram_frame_size of RFC 9221), as the
  # quic_transport_parameters extension carries them. The names are the
  # RFC's. Times are Float seconds, milliseconds on the wire. A parameter
  # left out has its default: max_idle_timeout 0 is no timeout, and
  # max_datagram_frame_size 0 is no DATAGRAM frames.
  class TransportParameters < Data.define(
    :max_idle_timeout, :max_udp_payload_size,
    :initial_max_data, :initial_max_stream_data_bidi_local, :initial_max_stream_data_bidi_remote, :initial_max_stream_data_uni,
    :initial_max_streams_bidi, :initial_max_streams_uni,
    :ack_delay_exponent, :max_ack_delay, :disable_active_migration, :active_connection_id_limit,
    :max_datagram_frame_size
  )
    IDS = {
      max_idle_timeout: 0x01, max_udp_payload_size: 0x03,
      initial_max_data: 0x04, initial_max_stream_data_bidi_local: 0x05, initial_max_stream_data_bidi_remote: 0x06,
      initial_max_stream_data_uni: 0x07, initial_max_streams_bidi: 0x08, initial_max_streams_uni: 0x09,
      ack_delay_exponent: 0x0a, max_ack_delay: 0x0b, disable_active_migration: 0x0c, active_connection_id_limit: 0x0e,
      max_datagram_frame_size: 0x20
    }.freeze #: Hash[Symbol, Integer]
    NAMES = IDS.invert.freeze #: Hash[Integer, Symbol]
    MILLISECONDS = %i[max_idle_timeout max_ack_delay].freeze
    MAX_STREAM_COUNT = 1 << 60

    # The rules of RFC 9000 "Transport Parameter Definitions" on the values.
    def initialize(
      max_idle_timeout: 0.0, max_udp_payload_size: 65_527,
      initial_max_data: 0, initial_max_stream_data_bidi_local: 0, initial_max_stream_data_bidi_remote: 0, initial_max_stream_data_uni: 0,
      initial_max_streams_bidi: 0, initial_max_streams_uni: 0,
      ack_delay_exponent: 3, max_ack_delay: 0.025, disable_active_migration: false, active_connection_id_limit: 2,
      max_datagram_frame_size: 0
    )
      raise ArgumentError, "max_idle_timeout #{max_idle_timeout} is negative" if max_idle_timeout.negative?
      raise ArgumentError, "max_udp_payload_size #{max_udp_payload_size} is under 1200" if max_udp_payload_size < 1200
      raise ArgumentError, "ack_delay_exponent #{ack_delay_exponent} is over 20" if ack_delay_exponent > 20
      raise ArgumentError, "max_ack_delay #{max_ack_delay} is 2^14 milliseconds or more" if max_ack_delay * 1000 >= 1 << 14
      raise ArgumentError, "active_connection_id_limit #{active_connection_id_limit} is under 2" if active_connection_id_limit < 2
      [initial_max_streams_bidi, initial_max_streams_uni].each do |count|
        raise ArgumentError, "a stream count of #{count} is past 2^60" if count > MAX_STREAM_COUNT
      end
      super
    end

    DEFAULTS = new.to_h.freeze

    # The parameters as the extension carries them, in the order of their
    # IDs, those at their defaults left out.
    def encode
      writer = Wire::Writer.new
      to_h.each do |name, value|
        next if value == DEFAULTS.fetch(name)
        body = case value
          when true then ""
          when Float then Wire::Varint.encode((value * 1000).round)
          else Wire::Varint.encode(value)
          end
        writer.varint(IDS.fetch(name)).varint(body.bytesize).bytes(body)
      end
      writer.to_s
    end

    # The parameters in `bytes`, from the peer. Unknown parameters, the
    # reserved ones for GREASE among them, are ignored (RFC 9000 "Reserved
    # Transport Parameters"). Anything else that is not right raises
    # Wire::Malformed with TRANSPORT_PARAMETER_ERROR.
    def self.decode(bytes)
      reader = Wire::Reader.new(bytes)
      parameters = {} #: Hash[Symbol, Integer | Float | bool]
      until reader.eof?
        id = reader.varint
        value = reader.sub(reader.varint)
        name = NAMES[id] or next
        parameters[name] = read_value(name, value)
        raise Wire::Malformed, "#{name} has #{value.remaining} bytes past its value" unless value.eof?
      end
      begin
        new(**parameters)
      rescue ArgumentError => error
        raise Wire::Malformed, error.message
      end
    rescue Wire::Malformed => error
      raise Wire::Malformed.new(error.message, code: ErrorCode::TRANSPORT_PARAMETER_ERROR)
    end

    private_class_method def self.read_value(name, value)
      case name
      when :disable_active_migration then true
      when *MILLISECONDS then value.varint / 1000.0
      else value.varint
      end
    end
  end
end
