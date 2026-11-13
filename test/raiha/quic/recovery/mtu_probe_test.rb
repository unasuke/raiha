require "test_helper"
require "support/quic_recovery"

# A probe of the path MTU, acknowledged or lost, goes to the search of the
# path that sent it, with its size; a probe declared lost and acknowledged
# after all is through.
class RaihaNextQUICRecoveryMTUProbeTest < Minitest::Test
  include NextQUICRecovery

  # A server's loss recovery on a path searching up to 1472 bytes.
  def searching
    recovery = recovery(role: :server)
    recovery.path.search_mtu(up_to: 1472)
    recovery
  end

  # Sends a probe of `size` at `now` and gives its number.
  def send_probe(recovery, size, now:)
    number = recovery.next_packet_number(:one_rtt)
    recovery.path.mtu_probe_sent(size)
    recovery.on_packet_sent(packet_type: :one_rtt, packet_number: number, sent_bytes: size, ack_eliciting: true, in_flight: true,
      duties: [], now:, pmtu_probe: true)
    number
  end

  def test_a_probe_acknowledged
    recovery = searching
    number = send_probe(recovery, 1472, now: 0.0)
    recovery.on_ack_received(packet_type: :one_rtt, ack: ack(number..number), now: 0.05)
    assert_equal 1472, recovery.path.max_datagram_size
  end

  # Three losses in a row of the largest, and the search goes halfway.
  def test_probes_lost
    recovery = searching
    3.times do |round|
      send_probe(recovery, 1472, now: round * 0.1)
      sent = Array.new(3) { send_packet(recovery, :one_rtt, now: round * 0.1) }
      recovery.on_ack_received(packet_type: :one_rtt, ack: ack(sent.last..sent.last), now: round * 0.1 + 0.05)
    end
    assert_equal [1200, 1336], [recovery.path.max_datagram_size, recovery.path.mtu_probe_size]
  end

  def test_a_probe_lost_and_acknowledged_after_all
    recovery = searching
    number = send_probe(recovery, 1472, now: 0.0)
    sent = Array.new(3) { send_packet(recovery, :one_rtt, now: 0.0) }
    recovery.on_ack_received(packet_type: :one_rtt, ack: ack(sent.last..sent.last), now: 0.05)
    assert_equal 1200, recovery.path.max_datagram_size
    recovery.on_ack_received(packet_type: :one_rtt, ack: ack(sent.last..sent.last, number..number), now: 0.1)
    assert_equal 1472, recovery.path.max_datagram_size
  end
end
