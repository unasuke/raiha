require "test_helper"
require "raiha/tls"

# The in-memory anti-replay record: each binder accepted once, kept for 11
# to 22 seconds by the clock it is given, and nothing accepted for the
# first 11 seconds unless told the keys are new.
class RaihaTLSAntiReplayTest < Minitest::Test
  Memory = Raiha::TLS::AntiReplay::Memory
  NOW = Time.at(1_800_000_000)
  A = ("\x01".b * 32).freeze
  B = ("\x02".b * 32).freeze

  def check(record, binder, at) = record.check(binder, expires_at: at + 11, now: at)

  def test_a_binder_is_accepted_once
    record = Memory.new(now: NOW, warmup: false)
    assert_equal :accepted, check(record, A, NOW)
    assert_equal :replayed, check(record, A, NOW + 1)
    assert_equal :accepted, check(record, B, NOW + 1)
  end

  # RFC 9846 "Client Hello Recording": no 0-RTT while the window overlaps
  # the start, though what comes is recorded.
  def test_the_first_11_seconds
    record = Memory.new(now: NOW)
    assert_equal :unavailable, check(record, A, NOW)
    assert_equal :replayed, check(record, A, NOW + 5)
    assert_equal :unavailable, check(record, B, NOW + 10)
    assert_equal :accepted, check(record, "\x03".b * 32, NOW + 11)
  end

  # A record is kept at least 11 seconds, and dropped by 22.
  def test_how_long_a_record_is_kept
    record = Memory.new(now: NOW, warmup: false)
    assert_equal :accepted, check(record, A, NOW + 10)
    assert_equal :replayed, check(record, A, NOW + 20)
    assert_equal :accepted, check(record, B, NOW + 21)
    assert_equal :accepted, check(record, A, NOW + 33)
    assert_equal :replayed, check(record, B, NOW + 33)
  end

  # A clock that goes back drops nothing.
  def test_a_clock_that_goes_back
    record = Memory.new(now: NOW, warmup: false)
    assert_equal :accepted, check(record, A, NOW + 5)
    assert_equal :replayed, check(record, A, NOW - 30)
  end

  # A record asked to outlive the window could not tell a replay then.
  def test_an_expiry_past_the_window
    record = Memory.new(now: NOW, warmup: false)
    assert_equal :unavailable, record.check(A, expires_at: NOW + 12, now: NOW)
    assert_equal :accepted, record.check(A, expires_at: NOW + 11, now: NOW)
  end

  def test_arguments
    assert_raises(ArgumentError) { Memory.new(now: 0) }
    assert_raises(ArgumentError) { Memory.new(now: NOW, warmup: nil) }
  end
end
