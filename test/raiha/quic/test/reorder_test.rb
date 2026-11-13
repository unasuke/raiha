require "test_helper"
require "raiha/quic/test"

class RaihaNextQUICTestReorderTest < Minitest::Test
  Test = Raiha::QUIC::Test

  def datagram(n) = Test::Datagram.new(payload: n.to_s, source: ["192.0.2.1", 1], destination: ["192.0.2.2", 2], ecn: :not_ect)

  def deliveries(path, now)
    delivered = []
    path.each_delivery(now:) { delivered << _1.payload }
    delivered
  end

  # A datagram held back goes right after the next one.
  def test_the_next_one_goes_past
    path = Test::Reorder.new(rate: 1.0).start(random: Random.new(1))
    path.submit(datagram(0), now: 0.0)
    assert_empty deliveries(path, 0.0)
    path.submit(datagram(1), now: 0.001)
    assert_equal %w[1 0], deliveries(path, 0.001)
    assert_nil path.next_timeout
  end

  # With nothing behind it, after `hold`.
  def test_held_at_most_hold
    path = Test::Reorder.new(rate: 1.0, hold: 0.02).start(random: Random.new(1))
    path.submit(datagram(0), now: 1.0)
    assert_in_delta 1.02, path.next_timeout
    assert_empty deliveries(path, 1.01)
    assert_equal %w[0], deliveries(path, 1.02)
  end

  def test_about_the_rate_and_nothing_lost
    path = Test::Reorder.new(rate: 0.1).start(random: Random.new(5))
    delivered = []
    10_000.times do |n|
      path.submit(datagram(n), now: n * 0.001)
      delivered.concat(deliveries(path, n * 0.001))
    end
    delivered.concat(deliveries(path, 100.0))
    assert_equal (0...10_000).map(&:to_s), delivered.sort_by(&:to_i)
    swapped = delivered.each_cons(2).count { |a, b| a.to_i > b.to_i }
    assert_in_delta 900, swapped, 150
  end

  def test_arguments
    assert_raises(ArgumentError) { Test::Reorder.new(rate: -0.1) }
    assert_raises(ArgumentError) { Test::Reorder.new(rate: 0.1, hold: 0.0) }
    assert Ractor.shareable?(Test::Reorder.new(rate: 0.1))
  end
end
