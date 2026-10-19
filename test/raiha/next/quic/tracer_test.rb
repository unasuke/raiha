require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICTracerTest < Minitest::Test
  # Only the events it cares about; the rest are there and do nothing.
  class LossOnly
    include Raiha::Next::QUIC::Tracer

    attr_reader :lost

    def initialize = @lost = []

    def packet_lost(packet_number:, **) = @lost << packet_number
  end

  def test_every_method_is_optional
    tracer = LossOnly.new
    tracer.packet_lost(packet_number: 3, space: :application_data, trigger: :time_threshold, mtu_probe: false, now: 1.0)
    assert_equal [3], tracer.lost
    assert_nil tracer.metrics_updated(now: 1.0, smoothed_rtt: 0.1)
    assert_nil tracer.timer_updated(timer_type: :loss_timeout, event_type: :set, space: :initial, delta: 0.5, now: 1.0)
    assert_nil tracer.ecn_state_updated(old: :testing, new: :capable, now: 1.0)
    assert_nil tracer.recovery_parameters_set(now: 1.0, reordering_threshold: 3)
    assert_nil tracer.spurious_loss(packet_number: 3, space: :application_data, now: 1.0)
    assert_nil tracer.congestion_state_updated(old: :slow_start, new: :recovery, now: 1.0)
    header = Raiha::Next::QUIC::Tracer::PacketHeader.of(Raiha::Next::QUIC::Wire::ShortHeader.new(dcid: "d".b), 7)
    assert_nil tracer.packet_sent(header:, frames: nil, raw_length: 40, now: 1.0)
    assert_nil tracer.packet_received(header:, frames: nil, raw_length: 40, now: 1.0)
    refute tracer.trace_frames?
  end

  # A short header has the Key Phase bit and no version or Source
  # Connection ID.
  def test_the_packet_header_of_a_short_header
    header = Raiha::Next::QUIC::Tracer::PacketHeader.of(Raiha::Next::QUIC::Wire::ShortHeader.new(dcid: "d".b, key_phase: 1), 7)
    assert_equal Raiha::Next::QUIC::Tracer::PacketHeader.new(packet_type: :one_rtt, packet_number: 7, version: nil, dcid: "d".b, scid: nil,
      key_phase: 1), header
  end
end
