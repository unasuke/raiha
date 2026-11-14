require "test_helper"
require "raiha/quic"

class RaihaQUICCongestionAlgorithmsTest < Minitest::Test
  Congestion = Raiha::QUIC::Congestion

  def test_resolve
    assert_same Congestion::NewReno, Congestion.resolve(:new_reno)
    assert_same Congestion::NewReno, Congestion.resolve(Congestion::NewReno)
    own = Class.new(Congestion::NewReno)
    assert_same own, Congestion.resolve(own)
    assert_raises(ArgumentError) { Congestion.resolve(:bbr) }
  end

  def test_shareable
    assert Ractor.shareable?(Congestion::ALGORITHMS)
  end
end
