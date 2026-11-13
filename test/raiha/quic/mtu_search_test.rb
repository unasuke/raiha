require "test_helper"
require "raiha/quic"

# The search of a path for the largest datagram it carries: the largest
# first, then halfway between, one probe at a time, a size given up on
# after three losses in a row.
class RaihaQUICMTUSearchTest < Minitest::Test
  QUIC = Raiha::QUIC

  def search(from: 1200, up_to: 1472) = QUIC::MTUSearch.new(from:, up_to:)

  # Each size probed, lost `losses[size]` times before it gets through,
  # or given up on when that is three or more, until the search is done.
  def probes(search, losses)
    sizes = []
    while (size = search.next_size)
      sizes << size
      search.sent(size)
      next search.acked(size) if losses.fetch(size, 0) < QUIC::MTUSearch::MAX_LOSSES
      search.lost(size)
    end
    sizes
  end

  # The largest gets through: one probe, and done.
  def test_the_largest_first
    search = search()
    assert_equal 1472, search.next_size
    search.sent(1472)
    assert_nil search.next_size
    assert_equal 1472, search.acked(1472)
    assert search.done?
    assert_nil search.next_size
  end

  # Each size goes again until lost three times in a row; then halfway
  # between, until what got through and what did not are 20 bytes apart.
  def test_halfway_between
    search = search()
    assert_equal [1472, 1472, 1472, 1336, 1404, 1404, 1404, 1370, 1387], probes(search, { 1472 => 3, 1404 => 3 })
    assert search.done?
  end

  # A probe that gets through starts the losses over; one lost of a size
  # no larger than what got through tells nothing.
  def test_losses_in_a_row
    search = search()
    2.times { search.lost(1472) }
    search.acked(1250)
    search.lost(1250)
    search.lost(1472)
    refute search.done?
    assert_equal 1472, search.next_size
  end

  # A size given up on, its probe late through, is through.
  def test_a_late_probe_through
    search = search()
    3.times { search.lost(1472) }
    assert_equal 1336, search.next_size
    assert_equal 1472, search.acked(1472)
    assert search.done?
  end

  # Nothing larger to look for: no probe.
  def test_nothing_to_look_for
    assert_nil search(up_to: 1200).next_size
    assert_nil search(from: 1350, up_to: 1300).next_size
  end
end
