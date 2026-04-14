# frozen_string_literal: true

require_relative "quic/protocol/version"
require_relative "quic/handshake/transport_parameters"

module Raiha
  class Config
    attr_accessor :max_idle_timeout
    attr_accessor :max_udp_payload_size
    attr_accessor :handshake_timeout

    attr_accessor :initial_max_data
    attr_accessor :initial_max_stream_data_bidi_local
    attr_accessor :initial_max_stream_data_bidi_remote
    attr_accessor :initial_max_stream_data_uni
    attr_accessor :initial_max_streams_bidi
    attr_accessor :initial_max_streams_uni

    attr_accessor :max_ack_delay
    attr_accessor :ack_delay_exponent

    attr_accessor :alpn_protocols
    attr_accessor :versions

    def initialize
      @max_idle_timeout = 30_000
      @max_udp_payload_size = 1200
      @handshake_timeout = 10_000

      @initial_max_data = 10 * 1024 * 1024
      @initial_max_stream_data_bidi_local = 1024 * 1024
      @initial_max_stream_data_bidi_remote = 1024 * 1024
      @initial_max_stream_data_uni = 1024 * 1024
      @initial_max_streams_bidi = 100
      @initial_max_streams_uni = 100

      @max_ack_delay = 25
      @ack_delay_exponent = 3

      @alpn_protocols = []
      @versions = [Quic::Protocol::Version::V1]
    end

    def self.client_default
      self.new
    end

    def self.server_default
      self.new
    end

    def to_transport_parameters
      Quic::Handshake::TransportParameters.new.tap do |transport_parameters|
        transport_parameters.max_idle_timeout = @max_idle_timeout
        transport_parameters.max_udp_payload_size = @max_udp_payload_size
        transport_parameters.initial_max_data = @initial_max_data
        transport_parameters.initial_max_stream_data_bidi_local = @initial_max_stream_data_bidi_local
        transport_parameters.initial_max_stream_data_bidi_remote = @initial_max_stream_data_bidi_remote
        transport_parameters.initial_max_stream_data_uni = @initial_max_stream_data_uni
        transport_parameters.initial_max_streams_bidi = @initial_max_streams_bidi
        transport_parameters.initial_max_streams_uni = @initial_max_streams_uni
        transport_parameters.max_ack_delay = @max_ack_delay
        transport_parameters.ack_delay_exponent = @ack_delay_exponent
      end
    end
  end
end
