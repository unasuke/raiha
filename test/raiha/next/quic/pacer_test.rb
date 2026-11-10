require "raiha/next/test_helper"
require "raiha/next/quic"

# The token bucket a path paces with: a burst of its capacity, then a
# datagram at a time as the rate fills it, the wait rounded up to the
# granularity, and no saving up past one burst, a burst being what the
# rate gives in one granularity when that is more than the capacity.
class RaihaNextQUICPacerTest < Minitest::Test
  Pacer = Raiha::Next::QUIC::Pacer
  MDS = 1200
  # 1,200 bytes a millisecond.
  RATE = 1_200_000.0

  # A full bucket at 0.0.
  def full_pacer = Pacer.new(capacity: 10 * MDS, granularity: 0.001).tap { _1.ready?(MDS, RATE, 0.0) }

  # A burst grown with the datagrams: what the bucket holds stays, and it
  # fills up to the new capacity.
  def test_a_new_capacity
    pacer = full_pacer
    pacer.capacity = 20 * MDS
    assert pacer.ready?(10 * MDS, RATE, 0.0)
    refute pacer.ready?(10 * MDS + 1, RATE, 0.0)
    assert pacer.ready?(20 * MDS, RATE, 0.1)
  end

  def test_a_burst_of_its_capacity
    pacer = full_pacer
    10.times do
      assert pacer.ready?(MDS, RATE, 0.0)
      pacer.sent(MDS)
    end
    refute pacer.ready?(MDS, RATE, 0.0)
    assert pacer.ready?(MDS, RATE, 0.001)
  end

  # The wait for the tokens of a datagram, rounded up to the granularity:
  # 2.5 ms at 480,000 bytes a second is 3.
  def test_when_a_datagram_may_go
    pacer = full_pacer
    pacer.sent(10 * MDS)
    assert_in_delta 0.001, pacer.release_at(MDS, RATE, 0.0), 1e-9
    assert_in_delta 0.003, pacer.release_at(MDS, 480_000.0, 0.0), 1e-9
    assert_nil pacer.release_at(MDS, RATE, 0.001)
  end

  # An idle path saves up one burst, no more.
  def test_no_more_than_one_burst_after_idling
    pacer = full_pacer
    pacer.sent(10 * MDS)
    assert pacer.ready?(MDS, RATE, 10.0)
    sent = 0
    sent += MDS while pacer.ready?(MDS, RATE, 10.0) && pacer.sent(MDS)
    assert_equal 10 * MDS, sent
  end

  # At 24,000 bytes a millisecond the rate gives twenty datagrams in one
  # granularity, twice the capacity: the bucket holds those twenty, so that
  # waking once a millisecond does not slow the rate down, and no more after
  # idling.
  def test_a_granularity_of_the_rate_above_the_capacity
    pacer = full_pacer
    pacer.sent(10 * MDS)
    [0.001, 10.0].each do |now|
      sent = 0
      sent += MDS while pacer.ready?(MDS, 24_000_000.0, now) && pacer.sent(MDS)
      assert_equal 20 * MDS, sent
    end
  end

  # No rate, before an RTT sample, is no pacing: the bucket is full again.
  def test_no_rate
    pacer = full_pacer
    pacer.sent(20 * MDS)
    assert pacer.ready?(MDS, nil, 0.0)
    assert_nil pacer.release_at(MDS, nil, 0.0)
  end

  # A datagram that went without waiting still takes its bytes.
  def test_what_went_without_waiting
    pacer = full_pacer
    pacer.sent(12 * MDS)
    refute pacer.ready?(MDS, RATE, 0.0)
    assert_in_delta 0.003, pacer.release_at(MDS, RATE, 0.0), 1e-9
  end
end
