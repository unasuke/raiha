require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICCongestionAlgorithmsTest < Minitest::Test
  Congestion = Raiha::Next::QUIC::Congestion

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
