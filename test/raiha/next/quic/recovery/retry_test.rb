require "raiha/next/test_helper"
require "raiha/next/support/quic_recovery"

# RFC 9002 "Handling Retry Packets", as loss recovery's design, "On a
# Retry", applies it.
class RaihaNextQUICRecoveryRetryTest < Minitest::Test
  include NextQUICRecovery

  Duty = QUIC::Recovery::Duty

  def test_a_retry
    recovery = recovery(role: :client)
    client_hello = Duty::Crypto.new(space: :initial, offset: 0, length: 300)
    early_data = Duty::Stream.new(stream_id: 0, offset: 0, length: 100, fin: true)
    send_packet(recovery, :initial, now: 1.0, duties: [client_hello])
    send_packet(recovery, :initial, now: 1.01, sent_bytes: 50, ack_eliciting: false, in_flight: false)
    send_packet(recovery, :zero_rtt, now: 1.02, duties: [early_data])
    window = recovery.path.congestion
    outcome = recovery.on_retry(now: 1.1)
    # The ClientHello and the 0-RTT data go back to be sent again.
    assert_equal [[client_hello], [early_data]], outcome.lost.map(&:duties)
    assert_empty outcome.acked
    # The path starts over, with the time to the Retry as its first sample.
    path = recovery.path
    assert_equal [0, 0], [path.bytes_in_flight, path.packets_in_flight]
    refute_same window, path.congestion
    assert_in_delta 0.1, path.rtt.smoothed_rtt
    assert_equal 1.1, path.rtt.first_sample_at
    # The packet numbers go on.
    assert_equal [2, 1], [recovery.next_packet_number(:initial), recovery.next_packet_number(:zero_rtt)]
    # With nothing in flight the client still keeps a PTO from now.
    assert_in_delta 1.1 + 0.1 + 4 * 0.05, recovery.next_timeout
  end

  # No sample once a PTO ran out: which Initial the Retry answers is not
  # known.
  def test_no_sample_after_a_pto
    recovery = recovery(role: :client)
    send_packet(recovery, :initial, now: 0.0)
    recovery.on_timeout(now: 1.0)
    send_packet(recovery, :initial, now: 1.0)
    recovery.on_retry(now: 1.2)
    assert_nil recovery.path.rtt.first_sample_at
    assert_equal 0, recovery.pto_count
  end

  def test_the_sample_is_5_ms_at_least
    recovery = recovery(role: :client)
    send_packet(recovery, :initial, now: 1.0)
    recovery.on_retry(now: 1.001)
    assert_in_delta 0.005, recovery.path.rtt.smoothed_rtt
  end
end
