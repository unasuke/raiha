require "raiha/next/test_helper"
require "raiha/next/runtime"

# Two workers of a server, in one Ractor here: what one hands on reaches the
# other's queue through its own thread, up to QUEUE datagrams; what comes to
# a worker's control port goes to the block, but a request for stats; and
# closing a worker ends its thread.
class RaihaNextRuntimeWorkerTest < Minitest::Test
  Worker = Raiha::Next::Runtime::Worker

  def setup
    inboxes = Array.new(2) { Ractor::Port.new }
    @workers = Array.new(2) do |id|
      Worker.new(id:, count: 2, sockets: [], inbox: inboxes[id], control: Ractor::Port.new, peers: inboxes,
        config: Raiha::Next::QUIC::Config.new(retry_token_key: "r".b * 32, stateless_reset_key: "k".b * 32),
      anti_replay: Raiha::Next::TLS::AntiReplay::Memory.new(now: Time.now))
    end
    @changes = Thread::Queue.new
    @controls = Thread::Queue.new
    @thrown = []
  end

  def teardown
    @workers.each(&:close)
  end

  def listen(worker) = worker.listen(changed: -> { @changes << worker.id }, failed: ->(error) { @thrown << error }) { |message| @controls << message }

  def forwarded(n) = ["datagram #{n}".b, ["192.0.2.1", 4433], ["192.0.2.2", 443], :not_ect, n.to_f]

  # Waits until `worker` has `n` datagrams handed on, and takes them.
  def taken(worker, n)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    taken = []
    taken.concat(worker.take) while taken.size < n && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline && sleep(0.001)
    taken
  end

  def test_what_one_worker_hands_on_reaches_the_other
    listen(@workers[1])
    @workers[0].forward(1, forwarded(1))
    assert_equal [forwarded(1)], taken(@workers[1], 1)
    assert_equal 1, @changes.pop(timeout: 1)
    assert_equal Worker::Stats.new(id: 0, sent: 1, received: 0, dropped: 0), @workers[0].stats
    assert_equal Worker::Stats.new(id: 1, sent: 0, received: 1, dropped: 0), @workers[1].stats
  end

  # Past QUEUE datagrams not taken, the newest are dropped and counted.
  def test_the_queue_drops_the_newest_when_full
    listen(@workers[1])
    (Worker::QUEUE + 3).times { |n| @workers[0].forward(1, forwarded(n)) }
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    sleep 0.001 until @workers[1].stats.dropped == 3 || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    stats = @workers[1].stats
    assert_equal [Worker::QUEUE, 3], [stats.received, stats.dropped]
    assert_equal (0...Worker::QUEUE).map { |n| forwarded(n) }, @workers[1].take
  end

  # A worker that has ended gets nothing, and the one handing on goes on.
  def test_nothing_is_handed_on_to_a_worker_that_has_ended
    @workers[1].close
    @workers[0].forward(1, forwarded(1))
    assert_equal 0, @workers[0].stats.sent
  end

  def test_the_control_port
    listen(@workers[0])
    @workers[0].control.send([:stop, 30])
    assert_equal [:stop, 30], @controls.pop(timeout: 1)
    reply = Ractor::Port.new
    @workers[0].control.send([:stats, reply])
    assert_equal Worker::Stats.new(id: 0, sent: 0, received: 0, dropped: 0), reply.receive
    assert_nil @controls.pop(timeout: 0.05)
  end

  # What comes to the control port is taken before datagrams handed on
  # that wait, so that a flood of them keeps no stop waiting.
  def test_the_control_port_goes_before_the_inbox
    100.times { |n| @workers[1].forward(0, forwarded(n)) }
    @workers[0].control.send([:stop, 30])
    order = Thread::Queue.new
    @workers[0].listen(changed: -> { order << :handed_on }, failed: ->(error) { @thrown << error }) { |message| order << message }
    assert_equal [:stop, 30], order.pop(timeout: 1)
  end

  def test_close_ends_the_thread
    listen(@workers[0])
    @workers[0].close
    assert @workers[0].inbox.closed?
    assert @workers[0].control.closed?
    @workers[0].close
  end

  def test_what_the_thread_raises_goes_to_failed
    @workers[0].listen(changed: -> { raise "boom" }, failed: ->(error) { @thrown << error }) { nil }
    @workers[1].forward(0, forwarded(1))
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    sleep 0.001 while @thrown.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    assert_equal ["boom"], @thrown.map(&:message)
  end
end
