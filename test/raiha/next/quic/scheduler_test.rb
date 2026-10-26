require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICSchedulerTest < Minitest::Test
  QUIC = Raiha::Next::QUIC

  # The turns `scheduler` gives, `count` of them.
  def turns(scheduler, count)
    Array.new(count) do
      stream_id = scheduler.current
      scheduler.advance
      stream_id
    end
  end

  def test_no_turns_at_first
    assert_nil QUIC::Scheduler.new.current
  end

  def test_streams_take_turns_in_the_order_they_became_ready
    scheduler = QUIC::Scheduler.new
    [8, 0, 4].each { |stream_id| scheduler.ready(stream_id) }
    assert_equal [8, 0, 4, 8, 0, 4], turns(scheduler, 6)
  end

  def test_ready_again_keeps_the_place
    scheduler = QUIC::Scheduler.new
    [0, 4].each { |stream_id| scheduler.ready(stream_id) }
    scheduler.ready(0)
    assert_equal [0, 4, 0], turns(scheduler, 3)
  end

  def test_a_stream_forgotten_takes_no_more_turns
    scheduler = QUIC::Scheduler.new
    [0, 4, 8].each { |stream_id| scheduler.ready(stream_id) }
    scheduler.forget(4)
    scheduler.forget(12)
    assert_equal [0, 8, 0], turns(scheduler, 3)
    scheduler.forget(0)
    scheduler.forget(8)
    assert_nil scheduler.current
  end
end
