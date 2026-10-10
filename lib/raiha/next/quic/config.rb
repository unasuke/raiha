# frozen_string_literal: true

module Raiha::Next::QUIC
  # What connections are set up with, one value for every connection of an
  # Endpoint and shareable between Ractors: the transport parameters this
  # end sends, named as RFC 9000 names them, and settings of this
  # implementation that never go on the wire. Certificates and keys, the
  # random source and the tracer are not here, since they cannot be shared
  # between Ractors; the TLS settings are in the TLS layer's Config.
  #
  # Times are Float seconds. max_datagram_frame_size nil (or 0) is no
  # DATAGRAM frames; RFC 9221 suggests 65535 to have them. max_udp_payload_size
  # is what this end can receive, and initial_max_datagram_size what it
  # sends before a path is probed: two things, however alike the names.
  class Config < Data.define(
    :max_idle_timeout, :max_udp_payload_size,
    :initial_max_data, :initial_max_stream_data_bidi_local, :initial_max_stream_data_bidi_remote, :initial_max_stream_data_uni,
    :initial_max_streams_bidi, :initial_max_streams_uni,
    :max_ack_delay, :ack_delay_exponent, :active_connection_id_limit, :disable_active_migration, :max_datagram_frame_size,
    :versions, :connection_id_length, :initial_max_datagram_size,
    :max_stream_receive_window, :max_receive_window, :max_send_buffer
  )
    TRANSPORT_PARAMETERS = %i[
      max_idle_timeout max_udp_payload_size
      initial_max_data initial_max_stream_data_bidi_local initial_max_stream_data_bidi_remote initial_max_stream_data_uni
      initial_max_streams_bidi initial_max_streams_uni
      max_ack_delay ack_delay_exponent active_connection_id_limit disable_active_migration max_datagram_frame_size
    ].freeze

    # Beside the rules of the transport parameters themselves: the versions
    # are supported ones, the connection IDs this end issues are 0 to 20
    # bytes, a datagram is 1200 bytes at least (RFC 9000 "Datagram Size"),
    # and the receive windows can grow from the initial ones: the stream
    # window to each initial stream limit, and the connection window to the
    # initial limit and to 1.5 times the stream window.
    def initialize(
      max_idle_timeout: 30.0, max_udp_payload_size: 65_527,
      initial_max_data: 768 * 1024, initial_max_stream_data_bidi_local: 512 * 1024,
      initial_max_stream_data_bidi_remote: 512 * 1024, initial_max_stream_data_uni: 512 * 1024,
      initial_max_streams_bidi: 100, initial_max_streams_uni: 3,
      max_ack_delay: 0.025, ack_delay_exponent: 3, active_connection_id_limit: 4, disable_active_migration: false,
      max_datagram_frame_size: nil,
      versions: [Version::V1], connection_id_length: 8, initial_max_datagram_size: 1200,
      max_stream_receive_window: 6 * 1024 * 1024, max_receive_window: 15 * 1024 * 1024, max_send_buffer: 15 * 1024 * 1024
    )
      TransportParameters.new(
        max_idle_timeout:, max_udp_payload_size:, initial_max_data:, initial_max_stream_data_bidi_local:,
        initial_max_stream_data_bidi_remote:, initial_max_stream_data_uni:, initial_max_streams_bidi:, initial_max_streams_uni:,
        max_ack_delay:, ack_delay_exponent:, active_connection_id_limit:, disable_active_migration:,
        max_datagram_frame_size: max_datagram_frame_size || 0
      )
      raise ArgumentError, "no versions" if versions.empty?
      versions.each { |version| raise ArgumentError, "#{version.inspect} is no supported version" unless Version::SUPPORTED.include?(version) }
      unless connection_id_length.between?(0, Wire::CONNECTION_ID_MAX_LENGTH)
        raise ArgumentError, "connection_id_length #{connection_id_length} is not 0 to 20"
      end
      raise ArgumentError, "initial_max_datagram_size #{initial_max_datagram_size} is under 1200" if initial_max_datagram_size < 1200
      [initial_max_stream_data_bidi_local, initial_max_stream_data_bidi_remote, initial_max_stream_data_uni].each do |initial|
        raise ArgumentError, "max_stream_receive_window #{max_stream_receive_window} is under #{initial}" if max_stream_receive_window < initial
      end
      raise ArgumentError, "max_receive_window #{max_receive_window} is under initial_max_data" if max_receive_window < initial_max_data
      if max_receive_window < max_stream_receive_window * 1.5
        raise ArgumentError, "max_receive_window #{max_receive_window} is under 1.5 times max_stream_receive_window"
      end
      raise ArgumentError, "max_send_buffer #{max_send_buffer} is not positive" unless max_send_buffer.positive?
      # A copy, so that making it shareable does not freeze the caller's.
      versions = Ractor.make_shareable(versions, copy: true)
      super
    end

    # The transport parameters a connection with these settings sends, with
    # its connection IDs and, for a server, its token and preferred address.
    def transport_parameters(
      initial_source_connection_id:, original_destination_connection_id: nil, retry_source_connection_id: nil,
      stateless_reset_token: nil, preferred_address: nil
    )
      parameters = to_h.slice(*TRANSPORT_PARAMETERS).merge(max_datagram_frame_size: max_datagram_frame_size || 0)
      TransportParameters.new(
        **parameters, initial_source_connection_id:, original_destination_connection_id:, retry_source_connection_id:,
        stateless_reset_token:, preferred_address:
      )
    end
  end
end
