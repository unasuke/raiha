require "test_helper"
require "raiha/quic/timer"

class RaihaQuicTimerTest < Minitest::Test
  def test_initial_state
    timer = Raiha::Quic::Timer.new
    refute timer.active?
    refute timer.expired?
    assert_nil timer.deadline
    assert_nil timer.remaining
  end

  def test_set_duration
    timer = Raiha::Quic::Timer.new
    timer.set(1.0)
    assert timer.active?
    refute timer.expired?
    assert timer.remaining > 0
  end

  def test_set_at
    timer = Raiha::Quic::Timer.new
    timer.set_at(Time.now + 10)
    assert timer.active?
    refute timer.expired?
  end

  def test_expired
    timer = Raiha::Quic::Timer.new
    timer.set_at(Time.now - 1)
    assert timer.expired?
    assert_equal 0, timer.remaining
  end

  def test_reset
    timer = Raiha::Quic::Timer.new
    timer.set(1.0)
    assert timer.active?
    timer.reset
    refute timer.active?
    assert_nil timer.deadline
  end

  def test_stop_alias
    timer = Raiha::Quic::Timer.new
    timer.set(1.0)
    timer.stop
    refute timer.active?
  end
end
