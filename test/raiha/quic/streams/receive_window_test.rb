require "test_helper"
require "raiha/quic"

# The receive window of a stream or of the connection: when credit goes,
# what it is, and how the window grows.
class RaihaNextQUICStreamsReceiveWindowTest < Minitest::Test
  QUIC = Raiha::QUIC
  ReceiveWindow = QUIC::Streams::ReceiveWindow
  STREAM = 0x0a

  def window(size: 1000, max: 4000, now: 0.0) = ReceiveWindow.new(size:, max:, now:)

  def test_the_peer_sends_up_to_the_limit
    w = window
    w.receive(1000, frame_type: STREAM)
    w.receive(400, frame_type: STREAM)
    assert_equal 1000, w.received
    error = assert_raises(QUIC::Violation) { w.receive(1001, frame_type: STREAM) }
    assert_equal [QUIC::ErrorCode::FLOW_CONTROL_ERROR, STREAM], [error.code, error.frame_type]
  end

  # A new limit is due once three quarters of the window or less is left,
  # and is what is consumed plus the window.
  def test_a_quarter_of_the_window
    w = window
    w.consume(249)
    refute w.update_due?
    w.consume(1)
    assert w.update_due?
    assert_equal 1250, w.advance(now: 0.0, rtt: nil)
    assert_equal 1250, w.limit
    refute w.update_due?
  end

  def test_the_limit_stops_at_two_to_the_62_less_one
    max = QUIC::Wire::Varint::MAX
    w = window(size: max - 100, max:)
    w.consume(max / 2)
    assert_equal max, w.advance(now: 0.0, rtt: nil)
    w.consume(1000)
    refute w.update_due?
  end

  # The window doubles when more than half of it was read in less than four
  # round trips' share of it.
  def test_the_window_doubles_when_read_fast
    w = window
    w.consume(600)
    assert_equal 2600, w.advance(now: 0.05, rtt: 0.1)
    assert_equal 2000, w.size
  end

  def test_the_window_stays_when_read_slowly
    w = window
    w.consume(600)
    assert_equal 1600, w.advance(now: 1.0, rtt: 0.1)
    assert_equal 1000, w.size
  end

  # The initial RTT is longer than most, and would make the window grow too
  # soon.
  def test_no_growth_before_the_first_rtt_sample
    w = window
    w.consume(600)
    w.advance(now: 0.05, rtt: nil)
    assert_equal 1000, w.size
  end

  def test_the_window_stops_at_its_maximum
    w = window(size: 3000)
    w.consume(2000)
    w.advance(now: 0.01, rtt: 0.1)
    assert_equal 4000, w.size
  end

  # Half the window or less read since it was last judged: it is judged
  # later, over the longer period.
  def test_a_period_goes_on_until_half_the_window_is_read
    w = window
    w.consume(300)
    w.advance(now: 0.01, rtt: 0.1)
    assert_equal 1000, w.size
    w.consume(300)
    w.advance(now: 0.02, rtt: 0.1)
    assert_equal 2000, w.size
  end

  # A peer blocked by the limit gets credit not yet told at once; one
  # blocked because nothing is read gets nothing.
  def test_a_blocked_peer
    w = window
    w.consume(100)
    refute w.update_due?
    w.blocked!
    assert w.update_due?
    assert_equal 1100, w.advance(now: 0.0, rtt: nil)
    w.blocked!
    refute w.update_due?
  end

  # A lost limit goes again only while it is the latest, as it was.
  def test_a_lost_limit
    w = window
    w.lost(1000)
    assert w.update_due?
    assert_equal 1000, w.advance(now: 0.0, rtt: nil)
    w.consume(300)
    w.advance(now: 0.0, rtt: nil)
    w.lost(1000)
    refute w.update_due?
  end

  # The connection's window follows a stream's, up to its own maximum.
  def test_growing_to_a_size
    w = window
    w.grow_to(1500, now: 0.0)
    assert_equal 1500, w.size
    w.grow_to(1200, now: 0.0)
    assert_equal 1500, w.size
    w.grow_to(9000, now: 0.0)
    assert_equal 4000, w.size
  end
end
