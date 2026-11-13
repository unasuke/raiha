require "test_helper"
require "raiha/quic/test"

class RaihaNextQUICCongestionNewRenoContractTest < Minitest::Test
  include Raiha::Next::QUIC::Test::CongestionContract

  def congestion_control = Raiha::Next::QUIC::Congestion::NewReno
end
