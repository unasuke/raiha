require "test_helper"
require "raiha/tls"

# The anti-replay record the Ractors of a process share: a binder accepted
# in one Ractor is a replay in another, and a check that the record does
# not answer, as it has stopped, cannot be read, or takes too long, is
# :unavailable rather than waiting for ever.
class RaihaTLSAntiReplaySharedTest < Minitest::Test
  Shared = Raiha::TLS::AntiReplay::Shared
  NOW = Time.at(1_800_000_000)
  A = ("\x01".b * 32).freeze

  def setup
    @shared, @ractor = Shared.start(now: NOW, warmup: false)
  end

  def teardown
    @shared.stop
    @ractor.join
  end

  def test_it_can_be_shared
    assert Ractor.shareable?(@shared)
  end

  def test_a_binder_is_taken_once_across_ractors
    assert_equal :accepted, @shared.check(A, expires_at: NOW + 11, now: NOW)
    other = Ractor.new(@shared, A, NOW) { |shared, binder, now| shared.check(binder, expires_at: now + 11, now: now + 1) }
    assert_equal :replayed, other.value
  end

  # The record answers what it fails on too, so that no check waits on it.
  def test_what_the_record_fails_on_is_unavailable
    assert_equal :unavailable, @shared.check(A, expires_at: Object.new, now: NOW) # steep:ignore
    assert_equal :accepted, @shared.check(A, expires_at: NOW + 11, now: NOW)
  end

  def test_a_record_that_has_stopped
    @shared.stop
    @ractor.join
    assert_equal :unavailable, @shared.check(A, expires_at: NOW + 11, now: NOW)
  end

  # A record that never answers: the check gives up after TIMEOUT.
  def test_a_record_that_does_not_answer
    silent = Shared.new(Ractor::Port.new)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_equal :unavailable, silent.check(A, expires_at: NOW + 11, now: NOW)
    assert_in_delta Shared::TIMEOUT, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, 0.1
  end

  # The warm-up of the record is kept: nothing accepted at first.
  def test_the_warmup
    shared, ractor = Shared.start(now: NOW)
    assert_equal :unavailable, shared.check(A, expires_at: NOW + 11, now: NOW)
    assert_equal :replayed, shared.check(A, expires_at: NOW + 11, now: NOW + 1)
  ensure
    shared&.stop
    ractor&.join
  end
end
