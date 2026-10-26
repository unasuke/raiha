# frozen_string_literal: true

require_relative "error"
require_relative "frame"

module Raiha::Next::HTTP3
  # The settings one end tells the other on its control stream (RFC 9114
  # "SETTINGS"): those of HTTP/3, of QPACK (RFC 9204 "Configuration"), of
  # Extended CONNECT (RFC 9220) and of HTTP Datagrams (RFC 9297).
  #
  # `max_field_section_size` nil is no limit, as a peer that does not say
  # gives. A setting at its default does not go in the frame.
  class Settings < Data.define(:qpack_max_table_capacity, :qpack_blocked_streams, :max_field_section_size, :h3_datagram, :enable_connect_protocol)
    QPACK_MAX_TABLE_CAPACITY = 0x01
    MAX_FIELD_SECTION_SIZE = 0x06
    QPACK_BLOCKED_STREAMS = 0x07
    ENABLE_CONNECT_PROTOCOL = 0x08
    H3_DATAGRAM = 0x33
    # The identifiers of HTTP/2's settings that HTTP/3 has none for, which
    # are never to come (RFC 9114 "Defined SETTINGS Parameters").
    HTTP2_IDENTIFIERS = [0x00, 0x02, 0x03, 0x04, 0x05].freeze
    # The settings that are 0 or 1.
    FLAGS = [ENABLE_CONNECT_PROTOCOL, H3_DATAGRAM].freeze

    # This end's: QPACK with no dynamic table, a field section of 64 KiB at
    # most, and HTTP Datagrams taken, so that taking them does not tell
    # what the end serves (RFC 9297 "The SETTINGS_H3_DATAGRAM HTTP/3
    # Setting").
    def initialize(qpack_max_table_capacity: 0, qpack_blocked_streams: 0, max_field_section_size: 65_536, h3_datagram: true, enable_connect_protocol: false)
      [qpack_max_table_capacity, qpack_blocked_streams, max_field_section_size].compact.each do |value|
        raise ArgumentError, "a setting is 0..2^62-1, not #{value.inspect}" unless value.is_a?(Integer) && value.between?(0, Varint::MAX)
      end
      [h3_datagram, enable_connect_protocol].each do |value|
        raise ArgumentError, "a flag is true or false, not #{value.inspect}" unless value == true || value == false
      end
      super
    end

    # The peer's, from its SETTINGS frame. An identifier that repeats, one
    # of HTTP/2, or a flag neither 0 nor 1 is H3_SETTINGS_ERROR; those not
    # known are ignored.
    def self.from_frame(frame)
      values = {} #: Hash[Integer, Integer]
      frame.settings.each do |identifier, value|
        if HTTP2_IDENTIFIERS.include?(identifier)
          raise Violation.new("the HTTP/2 setting 0x#{identifier.to_s(16)}", code: ErrorCode::SETTINGS_ERROR)
        end
        raise Violation.new("the setting 0x#{identifier.to_s(16)} twice", code: ErrorCode::SETTINGS_ERROR) if values.key?(identifier)
        if FLAGS.include?(identifier) && value > 1
          raise Violation.new("the setting 0x#{identifier.to_s(16)} is #{value}, not 0 or 1", code: ErrorCode::SETTINGS_ERROR)
        end
        values[identifier] = value
      end
      new(
        qpack_max_table_capacity: values.fetch(QPACK_MAX_TABLE_CAPACITY, 0), qpack_blocked_streams: values.fetch(QPACK_BLOCKED_STREAMS, 0),
        max_field_section_size: values[MAX_FIELD_SECTION_SIZE], h3_datagram: values[H3_DATAGRAM] == 1,
        enable_connect_protocol: values[ENABLE_CONNECT_PROTOCOL] == 1
      )
    end

    # The SETTINGS frame that tells these.
    def to_frame
      settings = [] #: Array[[Integer, Integer]]
      settings << [QPACK_MAX_TABLE_CAPACITY, qpack_max_table_capacity] unless qpack_max_table_capacity.zero?
      settings << [MAX_FIELD_SECTION_SIZE, max_field_section_size] if max_field_section_size
      settings << [QPACK_BLOCKED_STREAMS, qpack_blocked_streams] unless qpack_blocked_streams.zero?
      settings << [ENABLE_CONNECT_PROTOCOL, 1] if enable_connect_protocol
      settings << [H3_DATAGRAM, 1] if h3_datagram
      Frame::Settings.new(settings:)
    end
  end
end
