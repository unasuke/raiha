require "test_helper"
require "raiha/quic"

class RaihaQUICRememberedTransportParametersTest < Minitest::Test
  QUIC = Raiha::QUIC
  TP = QUIC::TransportParameters
  Remembered = QUIC::RememberedTransportParameters

  # RFC 9000 "Values of Transport Parameters for 0-RTT".
  MUST_NOT_REMEMBER = %i[
    ack_delay_exponent max_ack_delay initial_source_connection_id original_destination_connection_id
    preferred_address retry_source_connection_id stateless_reset_token
  ].freeze

  def server_parameters
    TP.new(
      original_destination_connection_id: "o".b * 8, max_idle_timeout: 30.0, stateless_reset_token: "s".b * 16,
      initial_max_data: 1 << 20, initial_max_streams_bidi: 100, ack_delay_exponent: 8, max_ack_delay: 0.05,
      preferred_address: TP::PreferredAddress.new(ipv4: ["192.0.2.1", 443], ipv6: nil, connection_id: "p".b * 8, stateless_reset_token: "r".b * 16),
      initial_source_connection_id: "c".b * 8, retry_source_connection_id: "y".b * 8, max_datagram_frame_size: 65_535
    )
  end

  def test_the_seven_are_not_there
    assert_equal TP.members - MUST_NOT_REMEMBER, Remembered.members
    remembered = server_parameters.remembered
    assert_equal server_parameters.to_h.slice(*Remembered.members), remembered.to_h
  end

  # Every parameter in the order of its ID, defaults included; the flag only
  # when set.
  def test_canonical_form
    expected = [
      "\x01\x01\x00", "\x03\x04\x80\x00\xff\xf7", "\x04\x01\x00", "\x05\x01\x00", "\x06\x01\x00", "\x07\x01\x00",
      "\x08\x01\x00", "\x09\x01\x00", "\x0e\x01\x02", "\x20\x01\x00"
    ].join.b
    assert_equal_bin expected, TP.new.remembered.encode
    with_flag = TP.new(disable_active_migration: true).remembered.encode
    assert_equal_bin expected.byteslice(0, 27) + "\x0c\x00".b + expected.byteslice(27..), with_flag
  end

  # The ticket context of a server stays the same across connections,
  # whose connection IDs and tokens differ, and changes with a limit.
  def test_what_changes_the_canonical_form
    canonical = server_parameters.remembered.encode
    other_connection = server_parameters.with(
      original_destination_connection_id: "O".b * 8, stateless_reset_token: "S".b * 16, initial_source_connection_id: "C".b * 8,
      retry_source_connection_id: nil, preferred_address: nil, ack_delay_exponent: 3, max_ack_delay: 0.025
    )
    assert_equal_bin canonical, other_connection.remembered.encode
    refute_equal canonical, server_parameters.with(initial_max_data: 1 << 19).remembered.encode
    refute_equal canonical, server_parameters.with(max_datagram_frame_size: 1200).remembered.encode
  end
end
