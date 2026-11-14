require "test_helper"
require "raiha/quic/test"

# One bottleneck link: bandwidth, delay, a tail-drop queue and CE marks.
class RaihaQUICTestBottleneckTest < Minitest::Test
  Test = Raiha::QUIC::Test

  def datagram(size, ecn: :ect0, name: size.to_s)
    Test::Datagram.new(payload: name.ljust(size, "x"), source: ["192.0.2.1", 1], destination: ["192.0.2.2", 2], ecn:)
  end

  def deliveries(path, now)
    delivered = []
    path.each_delivery(now:) { delivered << _1 }
    delivered
  end

  # 1000 bytes at 1 Mbps go out in 8 ms and arrive 10 ms later; the next one
  # waits for the first to go out.
  def test_bandwidth_and_delay
    path = Test::Bottleneck.new(bandwidth: 1_000_000, delay: 0.01, queue: 10_000).start(random: Random.new(1))
    path.submit(datagram(1000, name: "a"), now: 0.0)
    path.submit(datagram(1000, name: "b"), now: 0.0)
    assert_in_delta 0.018, path.next_timeout
    assert_empty deliveries(path, 0.0179)
    assert_equal ["a"], deliveries(path, path.next_timeout).map { _1.payload[0] }
    assert_in_delta 0.026, path.next_timeout
    assert_equal ["b"], deliveries(path, path.next_timeout).map { _1.payload[0] }
    assert_nil path.next_timeout
  end

  # A datagram that does not fit in what is left of the queue is dropped.
  def test_tail_drop
    path = Test::Bottleneck.new(bandwidth: 1_000_000, delay: 0.0, queue: 2500).start(random: Random.new(1))
    %w[a b c].each { path.submit(datagram(1000, name: _1), now: 0.0) }
    assert_equal %w[a b], deliveries(path, 1.0).map { _1.payload[0] }
    # Once the first has gone out there is room again.
    path.submit(datagram(1000, name: "d"), now: 1.0)
    path.submit(datagram(1000, name: "e"), now: 1.0)
    path.submit(datagram(1000, name: "f"), now: 1.0)
    assert_equal %w[d e], deliveries(path, 2.0).map { _1.payload[0] }
  end

  # ECT(0) finding more than the threshold waiting is marked CE; Not-ECT
  # and ECT(1) are not.
  def test_ce_marking
    path = Test::Bottleneck.new(bandwidth: 1_000_000, delay: 0.0, queue: 10_000, ce_threshold: 1500).start(random: Random.new(1))
    path.submit(datagram(1000, name: "a"), now: 0.0)
    path.submit(datagram(1000, name: "b"), now: 0.0)
    path.submit(datagram(1000, name: "c"), now: 0.0)
    path.submit(datagram(1000, ecn: :not_ect, name: "d"), now: 0.0)
    path.submit(datagram(1000, ecn: :ect1, name: "e"), now: 0.0)
    assert_equal %i[ect0 ect0 ce not_ect ect1], deliveries(path, 1.0).map(&:ecn)
    other = Test::Bottleneck.new(bandwidth: 1_000_000, delay: 0.0, queue: 10_000).start(random: Random.new(1))
    5.times { other.submit(datagram(1000), now: 0.0) }
    assert_equal [:ect0] * 5, deliveries(other, 1.0).map(&:ecn)
  end

  # On a network, the delay shows in the time things arrive.
  def test_on_a_network
    net = Test::Network.new(seed: 1)
    received = []
    sender = Object.new
    sent = false
    sender.define_singleton_method(:receive) { |*, **| }
    sender.define_singleton_method(:each_transmit) do |now:, &block|
      next if sent
      sent = true
      block.call(Raiha::QUIC::Transmit.new(payload: "x" * 1250, destination: ["192.0.2.2", 2], source: nil, ecn: :ect0, segment_size: nil))
    end
    sender.define_singleton_method(:next_timeout) { nil }
    sender.define_singleton_method(:handle_timeout) { |now:| }
    receiver = Object.new
    receiver.define_singleton_method(:receive) { |payload, from:, to:, ecn:, now:| received << now }
    receiver.define_singleton_method(:each_transmit) { |now:| }
    receiver.define_singleton_method(:next_timeout) { nil }
    receiver.define_singleton_method(:handle_timeout) { |now:| }
    net.add(sender, address: ["192.0.2.1", 1])
    net.add(receiver, address: ["192.0.2.2", 2])
    net.link(sender, receiver, model: Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.025, queue: 100_000))
    assert net.run_until { received.any? }
    assert_in_delta 0.026, received.first
  end

  def test_arguments
    assert_raises(ArgumentError) { Test::Bottleneck.new(bandwidth: 0, delay: 0.0, queue: 1) }
    assert_raises(ArgumentError) { Test::Bottleneck.new(bandwidth: 1, delay: -1.0, queue: 1) }
    assert_raises(ArgumentError) { Test::Bottleneck.new(bandwidth: 1, delay: 0.0, queue: 0) }
    assert_raises(ArgumentError) { Test::Bottleneck.new(bandwidth: 1, delay: 0.0, queue: 1, ce_threshold: -1) }
    assert Ractor.shareable?(Test::Bottleneck.new(bandwidth: 1, delay: 0.0, queue: 1, ce_threshold: 1))
  end
end
