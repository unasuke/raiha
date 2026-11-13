require "test_helper"
require "raiha/tls/test"

class RaihaNextTLSTestFixedRandomTest < Minitest::Test
  FixedRandom = Raiha::Next::TLS::Test::FixedRandom

  def test_hands_out_the_chunks_in_order
    random = FixedRandom.new("a" * 32, "b" * 4)
    assert_equal "a" * 32, random.bytes(32)
    assert_equal "b" * 4, random.bytes(4)
    assert_raises(ArgumentError) { random.bytes(1) }
  end

  def test_each_draw_must_match_the_next_chunk
    assert_raises(ArgumentError) { FixedRandom.new("a" * 32).bytes(16) }
  end
end
