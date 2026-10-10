# frozen_string_literal: true

module Raiha::Next::QUIC
  # The server's transport parameters that a client remembers for 0-RTT
  # (RFC 9000 "Values of Transport Parameters for 0-RTT"): every one but the
  # seven a client must not use remembered values of, which this type does
  # not have. Not holding them is what keeps them from being used.
  # max_datagram_frame_size is here too: a client that sends 0-RTT data
  # remembers every parameter it can process.
  class RememberedTransportParameters < Data.define(
    :max_idle_timeout, :max_udp_payload_size,
    :initial_max_data, :initial_max_stream_data_bidi_local, :initial_max_stream_data_bidi_remote, :initial_max_stream_data_uni,
    :initial_max_streams_bidi, :initial_max_streams_uni,
    :disable_active_migration, :active_connection_id_limit, :max_datagram_frame_size
  )
    # The canonical form: every parameter in the order of its ID, in the
    # transport parameters' wire form, defaults included. The server puts it
    # in the context of its tickets, so that a ticket's 0-RTT is refused
    # once any of these change. disable_active_migration, a flag, is there
    # only when true.
    def encode
      writer = Wire::Writer.new
      to_h.each { |name, value| TransportParameters.write(writer, name, value) }
      writer.to_s
    end
  end
end
