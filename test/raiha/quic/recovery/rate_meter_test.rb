require "test_helper"
require "raiha/quic"

# The bandwidth estimator of a path: samples of what was acknowledged while
# the sender was held back, 50 ms at least, the latest ten kept; nothing
# while it was not. The times are binary fractions, so that the periods add
# up exactly.
class RaihaNextQUICRecoveryRateMeterTest < Minitest::Test
  RateMeter = Raiha::Next::QUIC::Recovery::RateMeter

  def test_nothing_while_not_held_back
    meter = RateMeter.new
    meter.on_ack(1200, largest: 0, now: 0.0)
    meter.on_ack(1200, largest: 1, now: 0.125)
    assert_nil meter.rate
  end

  # Held back from packet 10: an ACK of packets before it counts for
  # nothing, the ACK of 10 starts a sample, and the bytes of the ACKs after
  # it over the time since make the rate, so far and once 50 ms are up.
  def test_a_sample_while_held_back
    meter = RateMeter.new
    meter.sending_stopped(limited: true, next_packet_number: 10)
    meter.on_ack(1200, largest: 9, now: 0.0)
    meter.on_ack(1200, largest: 10, now: 0.0)
    assert_nil meter.rate
    meter.on_ack(6000, largest: 15, now: 0.03125)
    assert_in_delta 192_000.0, meter.rate
    meter.on_ack(2000, largest: 17, now: 0.0625)
    assert_in_delta 128_000.0, meter.rate
  end

  # No longer held back from packet 10: the ACKs of those before it still
  # count, the first past it ends the sample, and the rest count for
  # nothing.
  def test_no_longer_held_back
    meter = RateMeter.new
    meter.sending_stopped(limited: true, next_packet_number: 0)
    meter.on_ack(1200, largest: 0, now: 0.0)
    meter.on_ack(4800, largest: 4, now: 0.015625)
    meter.sending_stopped(limited: false, next_packet_number: 10)
    meter.on_ack(4800, largest: 8, now: 0.03125)
    meter.on_ack(100_000, largest: 10, now: 0.046875)
    meter.on_ack(100_000, largest: 11, now: 0.5)
    assert_in_delta 307_200.0, meter.rate
  end

  # Held back again, the sample of the last time ends there, though no ACK
  # past it came.
  def test_held_back_again
    meter = RateMeter.new
    meter.sending_stopped(limited: true, next_packet_number: 0)
    meter.on_ack(0, largest: 0, now: 0.0)
    meter.on_ack(3000, largest: 2, now: 0.03125)
    meter.sending_stopped(limited: false, next_packet_number: 5)
    meter.sending_stopped(limited: true, next_packet_number: 20)
    meter.on_ack(1000, largest: 4, now: 0.5)
    meter.on_ack(0, largest: 20, now: 1.0)
    meter.on_ack(6000, largest: 22, now: 1.03125)
    assert_in_delta 144_000.0, meter.rate
  end

  # Eleven samples, the first at 800,000 bytes a second and the ten after
  # at 1,600,000: only the ten are kept.
  def test_the_latest_ten
    meter = RateMeter.new
    meter.sending_stopped(limited: true, next_packet_number: 0)
    meter.on_ack(0, largest: 0, now: 0.0)
    ([50_000] + [100_000] * 10).each.with_index(1) do |bytes, number|
      meter.on_ack(bytes, largest: number, now: number * 0.0625)
    end
    assert_in_delta 1_600_000.0, meter.rate
  end
end
