require "test_helper"
require "support/quic_recovery"

# RFC 9002 "Discarding Keys and Packet State", as loss recovery's design,
# "Discarding Initial and Handshake keys", applies it.
class RaihaQUICRecoveryDiscardTest < Minitest::Test
  include QUICRecovery

  # NewReno that keeps whether it heard anything.
  class Spy < Raiha::QUIC::Congestion::NewReno
    attr_reader :heard

    def on_loss(**) = (@heard = true) && super

    def on_ack(**) = (@heard = true) && super
  end

  def spied
    config = QUIC::Config.new(congestion_control: Spy)
    recovery(role: :server, config:, path: QUIC::Path.new(config:))
  end

  def test_discarding_the_initial_space
    recovery = spied
    2.times { send_packet(recovery, :initial, now: 0.0) }
    send_packet(recovery, :handshake, now: 0.5)
    recovery.on_timeout(now: 1.0)
    assert_equal 1, recovery.pto_count
    recovery.discard_space(:initial, now: 1.1)
    assert_equal [1200, 1, 0], [recovery.path.bytes_in_flight, recovery.path.packets_in_flight, recovery.pto_count]
    assert_in_delta 0.5 + 0.999, recovery.next_timeout
    assert_nil recovery.path.congestion.heard
    # Nothing of it is left to acknowledge or lose.
    assert_same QUIC::Recovery::Outcome::NONE, recovery.on_ack_received(packet_type: :initial, ack: ack(0..0), now: 1.2)
  end

  def test_nothing_left_in_flight
    recovery = spied
    send_packet(recovery, :handshake, now: 0.0)
    recovery.discard_space(:handshake, now: 0.1)
    assert_equal 0, recovery.path.bytes_in_flight
    assert_nil recovery.next_timeout
  end

  def test_application_data_is_never_discarded
    assert_raises(ArgumentError) { spied.discard_space(:one_rtt, now: 0.0) }
  end
end
