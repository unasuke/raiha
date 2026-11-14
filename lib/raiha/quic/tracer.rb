# frozen_string_literal: true

module Raiha::QUIC
  # What a tracer is told, one method per event of the qlog drafts. Every
  # method is optional: a tracer includes this module and overrides the ones
  # it wants, and the rest do nothing. The layer takes a tracer, or nil for
  # none, and calls it only when it has one, so that without a tracer not
  # even the arguments are made.
  #
  # Times are Float seconds of the monotonic clock; a qlog writer turns them
  # into milliseconds. `space` is :initial, :handshake or :application_data.
  module Tracer
    # A packet's header as qlog writes it (qlog `PacketHeader`): its type
    # and number, and the version and connection IDs of a long header or
    # the Key Phase bit of a short one.
    class PacketHeader < Data.define(:packet_type, :packet_number, :version, :dcid, :scid, :key_phase)
      # The header of the packet with the Wire header `header` numbered
      # `packet_number`.
      def self.of(header, packet_number)
        case header
        when Wire::LongHeader
          new(packet_type: header.type, packet_number:, version: header.version.number, dcid: header.dcid, scid: header.scid, key_phase: nil)
        else new(packet_type: :one_rtt, packet_number:, version: nil, dcid: header.dcid, scid: nil, key_phase: header.key_phase)
        end
      end
    end

    # A packet sent (qlog `packet_sent`) and one received and processed
    # (qlog `packet_received`): its PacketHeader, its frames when
    # `trace_frames?`, nil otherwise, and how many bytes it took.
    def packet_sent(header:, frames:, raw_length:, now:) = nil

    def packet_received(header:, frames:, raw_length:, now:) = nil

    # Whether `packet_sent` and `packet_received` are given the frames.
    def trace_frames? = false

    # Packets of `raw_length` bytes dropped (qlog `packet_dropped`).
    # `reason` is a trigger of qlog: :invalid, :unsupported,
    # :connection_unknown, :key_unavailable, :decryption_failure, :duplicate
    # or :general.
    def packet_dropped(reason:, raw_length:, now:) = nil

    # The transport parameters of this end (`owner` :local) or of the peer,
    # once authenticated (:remote) (qlog `parameters_set`).
    def parameters_set(owner:, parameters:, now:) = nil

    # The keys of `level` changed with a key update, which only :one_rtt
    # has (qlog `key_updated`).
    def key_updated(level:, now:) = nil

    # A packet declared lost (qlog `packet_lost`). `trigger` is
    # :reordering_threshold or :time_threshold.
    def packet_lost(packet_number:, space:, trigger:, mtu_probe:, now:) = nil

    # The values of loss recovery and congestion control that changed
    # (qlog `recovery_metrics_updated`).
    def metrics_updated(now:, **metrics) = nil

    # A timer set, expired or cancelled (qlog `timer_updated`). `timer_type`
    # is :loss_timeout or :ack, `event_type` :set, :expired or :cancelled,
    # and `delta` the seconds from now to the deadline when set.
    def timer_updated(timer_type:, event_type:, space:, delta:, now:) = nil

    # The ECN state of the path changed (qlog `ecn_state_updated`): :testing,
    # :capable or :failed.
    def ecn_state_updated(old:, new:, now:) = nil

    # The constants of loss recovery and congestion control, once at the
    # start of a connection (qlog `recovery_parameters_set`).
    def recovery_parameters_set(now:, **parameters) = nil

    # A packet declared lost and acknowledged after all; qlog has no event
    # for it, so a writer makes one of its own.
    def spurious_loss(packet_number:, space:, now:) = nil

    # The congestion controller changed state (qlog
    # `congestion_state_updated`). The states are the algorithm's own.
    def congestion_state_updated(old:, new:, now:) = nil

    # Sending on the connection, or on stream `stream_id`, became :blocked
    # by the peer's limit, `reason` :connection_flow_control or
    # :stream_flow_control, or :unblocked as the limit grew (qlog
    # `connection_data_blocked_updated` and `stream_data_blocked_updated`).
    def connection_data_blocked_updated(old:, new:, reason:, now:) = nil

    def stream_data_blocked_updated(stream_id:, old:, new:, reason:, now:) = nil

    # The datagrams of the path grew or shrank from `old` bytes to `new`,
    # or the search for its MTU ended at `old` (qlog `mtu_updated`); `done`
    # once the search has ended.
    def mtu_updated(old:, new:, done:, now:) = nil

    # The connection ID in use changed from `old` to `new` (qlog
    # `connection_id_updated`): the peer's this end sends with (`owner`
    # :remote), or this end's the peer sends with (:local).
    def connection_id_updated(owner:, old:, new:, now:) = nil

    # How a path between `local` and `remote` stands (qlog
    # `migration_state_updated`): :probing_started, :probing_successful
    # and :probing_abandoned as one besides the path in use is validated,
    # and :migration_started, :migration_complete and :migration_abandoned
    # as the connection moves to one.
    def migration_state_updated(state:, local:, remote:, now:) = nil
  end
end
