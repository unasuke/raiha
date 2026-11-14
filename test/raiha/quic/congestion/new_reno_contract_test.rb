require "test_helper"
require "raiha/quic/test"

class RaihaQUICCongestionNewRenoContractTest < Minitest::Test
  include Raiha::QUIC::Test::CongestionContract

  def congestion_control = Raiha::QUIC::Congestion::NewReno
end
