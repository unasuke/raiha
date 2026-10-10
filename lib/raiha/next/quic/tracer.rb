# frozen_string_literal: true

module Raiha::Next::QUIC
  # What a tracer is told, one method per event of the qlog drafts. Every
  # method is optional: a tracer includes this module and overrides the ones
  # it wants, and the rest do nothing. The layer takes a tracer, or nil for
  # none, and calls it only when it has one, so that without a tracer not
  # even the arguments are made.
  #
  # Times are Float seconds of the monotonic clock; a qlog writer turns them
  # into milliseconds. `space` is :initial, :handshake or :application_data.
  module Tracer
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
  end
end
