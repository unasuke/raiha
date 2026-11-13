require "test_helper"
require "raiha/quic/test"

class RaihaNextQUICTestRandomLossTest < Minitest::Test
  Test = Raiha::QUIC::Test

  def datagram(n) = Test::Datagram.new(payload: n.to_s, source: ["192.0.2.1", 1], destination: ["192.0.2.2", 2], ecn: :not_ect)

  def through(model, count, seed: 1)
    path = model.start(random: Random.new(seed))
    count.times { |n| path.submit(datagram(n), now: 0.0) }
    delivered = []
    path.each_delivery(now: 0.0) { delivered << _1.payload }
    delivered
  end

  # About the rate dropped, the rest at once and in order.
  def test_drops_about_the_rate
    delivered = through(Test::RandomLoss.new(rate: 0.2), 10_000)
    assert_in_delta 8000, delivered.size, 200
    assert_equal delivered.sort_by(&:to_i), delivered
    assert_nil Test::RandomLoss.new(rate: 0.2).start(random: Random.new(1)).next_timeout
  end

  def test_edges
    assert_equal 100, through(Test::RandomLoss.new(rate: 0.0), 100).size
    assert_empty through(Test::RandomLoss.new(rate: 1.0), 100)
    assert_raises(ArgumentError) { Test::RandomLoss.new(rate: 1.5) }
  end

  def test_same_seed_same_losses
    assert_equal through(Test::RandomLoss.new(rate: 0.5), 100, seed: 3), through(Test::RandomLoss.new(rate: 0.5), 100, seed: 3)
  end

  def test_shareable
    assert Ractor.shareable?(Test::RandomLoss.new(rate: 0.1))
  end
end
