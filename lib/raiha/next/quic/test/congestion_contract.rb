# frozen_string_literal: true

module Raiha::Next::QUIC::Test
  # What every congestion control algorithm keeps to, the application's own
  # included, as tests to include in a Minitest class that names the
  # algorithm:
  #
  #   class MyAlgorithmTest < Minitest::Test
  #     include Raiha::Next::QUIC::Test::CongestionContract
  #     def congestion_control = MyAlgorithm
  #   end
  module CongestionContract
    MAX_DATAGRAM_SIZE = 1200
    # The states of the algorithms that come with the layer and of those
    # 259 names; an algorithm of its own may add to them.
    KNOWN_STATES = %i[
      slow_start congestion_avoidance recovery application_limited reno_friendly concave convex rapid_start
    ].freeze
    SEED = 259

    # The states this algorithm may be in.
    def known_congestion_states = KNOWN_STATES

    def test_congestion_contract_window_stays_above_the_minimum
      cc = new_controller
      rng = Random.new(SEED)
      now = 0.0
      1000.times do
        now += rng.rand * 0.05
        case rng.rand(4)
        when 0, 1 then acknowledge(cc, rng.rand(1..10) * MAX_DATAGRAM_SIZE, sent_at: now - 0.1, now:, app_limited: rng.rand(4).zero?)
        when 2 then cc.on_loss(lost_bytes: MAX_DATAGRAM_SIZE, largest_lost_sent_at: now - rng.rand * 0.2, persistent: rng.rand(20).zero?, now:)
        else cc.on_ecn_ce(largest_acked_sent_at: now - rng.rand * 0.2, now:)
        end
        assert_operator cc.window, :>=, cc.minimum_window
      end
    end

    def test_congestion_contract_loss_shrinks_the_window
      cc = new_controller
      acknowledge(cc, 10 * MAX_DATAGRAM_SIZE, sent_at: 0.0, now: 0.1)
      before = cc.window
      cc.on_loss(lost_bytes: MAX_DATAGRAM_SIZE, largest_lost_sent_at: 0.2, persistent: false, now: 0.3)
      assert_operator cc.window, :<, before
    end

    def test_congestion_contract_persistent_congestion_takes_the_minimum
      cc = new_controller
      acknowledge(cc, 10 * MAX_DATAGRAM_SIZE, sent_at: 0.0, now: 0.1)
      cc.on_loss(lost_bytes: MAX_DATAGRAM_SIZE, largest_lost_sent_at: 0.2, persistent: true, now: 0.3)
      assert_equal cc.minimum_window, cc.window
    end

    def test_congestion_contract_minimum_follows_the_datagram_size
      cc = new_controller
      cc.on_mtu_updated(max_datagram_size: 1500, now: 0.0)
      assert_equal 3000, cc.minimum_window
      cc.on_loss(lost_bytes: 1500, largest_lost_sent_at: 0.1, persistent: true, now: 0.2)
      cc.on_mtu_updated(max_datagram_size: 4000, now: 0.3)
      assert_equal 8000, cc.minimum_window
      assert_operator cc.window, :>=, 8000
    end

    def test_congestion_contract_no_growth_while_application_limited
      cc = new_controller
      window = cc.window
      20.times do |i|
        acknowledge(cc, 4 * MAX_DATAGRAM_SIZE, sent_at: i * 0.1, now: i * 0.1 + 0.05, app_limited: true)
        assert_operator cc.window, :<=, window
      end
    end

    def test_congestion_contract_states_are_known
      cc = new_controller
      states = [cc.state]
      acknowledge(cc, MAX_DATAGRAM_SIZE, sent_at: 0.0, now: 0.1)
      states << cc.state
      acknowledge(cc, MAX_DATAGRAM_SIZE, sent_at: 0.1, now: 0.2, app_limited: true)
      states << cc.state
      cc.on_loss(lost_bytes: MAX_DATAGRAM_SIZE, largest_lost_sent_at: 0.15, persistent: false, now: 0.3)
      states << cc.state
      acknowledge(cc, MAX_DATAGRAM_SIZE, sent_at: 0.4, now: 0.5)
      states << cc.state
      states.each do |state|
        assert_kind_of Symbol, state
        assert_includes known_congestion_states, state
      end
    end

    def test_congestion_contract_metrics_carry_the_window
      cc = new_controller
      assert_equal cc.window, cc.metrics[:congestion_window]
      cc.on_loss(lost_bytes: MAX_DATAGRAM_SIZE, largest_lost_sent_at: 0.0, persistent: false, now: 0.1)
      assert_equal cc.window, cc.metrics[:congestion_window]
    end

    private def new_controller
      congestion_control.new(max_datagram_size: MAX_DATAGRAM_SIZE, initial_window: Raiha::Next::QUIC::Config::DEFAULT_INITIAL_WINDOW,
        config: Raiha::Next::QUIC::Config.new(congestion_control:))
    end

    private def acknowledge(cc, bytes, sent_at:, now:, app_limited: false)
      cc.on_ack(acked_bytes: bytes, largest_acked_sent_at: sent_at, latest_rtt: 0.1, smoothed_rtt: 0.1, min_rtt: 0.1, app_limited:, now:)
    end
  end
end
