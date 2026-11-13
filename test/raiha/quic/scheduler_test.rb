require "test_helper"
require "raiha/quic"

class RaihaQUICSchedulerTest < Minitest::Test
  QUIC = Raiha::QUIC

  # The turns `scheduler` gives, `count` of them.
  def turns(scheduler, count)
    Array.new(count) do
      stream_id = scheduler.current
      scheduler.advance
      stream_id
    end
  end

  def scheduler(*ready, **priorities)
    scheduler = QUIC::Scheduler.new
    priorities.each { |stream_id, (urgency, incremental)| scheduler.prioritize(Integer(stream_id.to_s.delete_prefix("s")), urgency:, incremental:) }
    ready.each { |stream_id| scheduler.ready(stream_id) }
    scheduler
  end

  def test_no_turns_at_first
    assert_nil QUIC::Scheduler.new.current
  end

  # Streams given no priority take turns alike, in the order they became
  # ready.
  def test_streams_take_turns_in_the_order_they_became_ready
    assert_equal [8, 0, 4, 8, 0, 4], turns(scheduler(8, 0, 4), 6)
  end

  def test_ready_again_keeps_the_place
    scheduler = scheduler(0, 4)
    scheduler.ready(0)
    assert_equal [0, 4, 0], turns(scheduler, 3)
  end

  def test_an_idle_stream_takes_no_turns_and_keeps_its_priority
    scheduler = scheduler(0, 4, s4: [1, true])
    scheduler.idle(4)
    scheduler.idle(12)
    assert_equal [0, 0], turns(scheduler, 2)
    scheduler.ready(4)
    assert_equal [4, 4], turns(scheduler, 2)
  end

  def test_a_stream_forgotten_takes_no_more_turns_nor_its_priority
    scheduler = scheduler(0, 4, s4: [1, true])
    scheduler.forget(4)
    assert_equal [0, 0], turns(scheduler, 2)
    scheduler.ready(4)
    assert_equal [0, 4, 0], turns(scheduler, 3)
    scheduler.forget(0)
    scheduler.forget(4)
    assert_nil scheduler.current
  end

  # RFC 9218 "Server Scheduling": higher urgency, the lower value, first.
  def test_the_most_urgent_streams_go_first
    scheduler = scheduler(0, 4, 8, s4: [1, true], s8: [7, true])
    assert_equal [4, 4], turns(scheduler, 2)
    scheduler.idle(4)
    assert_equal [0, 0], turns(scheduler, 2)
    scheduler.idle(0)
    assert_equal [8], turns(scheduler, 1)
  end

  # Those not incremental of one urgency go one by one, the lowest ID
  # first, however they became ready.
  def test_streams_not_incremental_go_one_by_one_by_id
    scheduler = scheduler(8, 0, 4, s0: [3, false], s4: [3, false], s8: [3, false])
    assert_equal [0, 0, 0], turns(scheduler, 3)
    scheduler.idle(0)
    assert_equal [4, 4], turns(scheduler, 2)
    scheduler.idle(4)
    assert_equal [8], turns(scheduler, 1)
  end

  # Neither kind starves the other: the incremental streams take turns
  # with the one not incremental of the lowest ID, whose place in the
  # turns the next of them takes.
  def test_incremental_streams_take_turns_with_the_first_not_incremental
    scheduler = scheduler(4, 1, 0, 5, s0: [3, false], s4: [3, false])
    assert_equal [0, 1, 5, 0, 1, 5], turns(scheduler, 6)
    scheduler.idle(0)
    assert_equal [4, 1, 5, 4], turns(scheduler, 4)
    scheduler.idle(4)
    assert_equal [1, 5, 1], turns(scheduler, 3)
  end

  def test_a_priority_given_while_ready_moves_the_stream_behind_the_others
    scheduler = scheduler(0, 4, 8)
    scheduler.prioritize(0, urgency: 3, incremental: true)
    assert_equal [0, 4], turns(scheduler, 2)
    scheduler.prioritize(8, urgency: 3, incremental: false)
    assert_equal [0, 4, 8, 0], turns(scheduler, 4)
    scheduler.prioritize(4, urgency: 0, incremental: true)
    assert_equal [4, 4], turns(scheduler, 2)
  end
end
