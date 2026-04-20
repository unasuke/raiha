require "test_helper"
require "raiha/quic/protocol"

class RaihaQuicProtocolPerspectiveTest < Minitest::Test
  Perspective = Raiha::Quic::Protocol::Perspective

  def test_client_and_server_predicates
    assert Perspective::CLIENT.client?
    refute Perspective::CLIENT.server?

    assert Perspective::SERVER.server?
    refute Perspective::SERVER.client?
  end

  def test_opposite_flips_role
    assert_equal Perspective::SERVER, Perspective::CLIENT.opposite
    assert_equal Perspective::CLIENT, Perspective::SERVER.opposite
  end

  def test_coerce_accepts_symbol
    assert_equal Perspective::CLIENT, Perspective.coerce(:client)
    assert_equal Perspective::SERVER, Perspective.coerce(:server)
  end

  def test_coerce_idempotent_on_existing_instance
    assert_same Perspective::CLIENT, Perspective.coerce(Perspective::CLIENT)
  end

  def test_coerce_rejects_invalid_input
    assert_raises(ArgumentError) { Perspective.coerce(:invalid) }
    assert_raises(ArgumentError) { Perspective.coerce("client") }
  end

  def test_equality_with_symbol
    assert_equal Perspective::CLIENT, :client
    refute_equal Perspective::CLIENT, :server
  end
end
