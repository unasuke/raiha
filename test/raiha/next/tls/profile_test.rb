require "raiha/next/test_helper"
require "raiha/next/tls"

class RaihaNextTLSProfileTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Profile = TLS::Profile

  # The RFC 9001 differences, flag by flag.
  def test_quic_differs_from_tcp_as_rfc_9001_requires
    differences = Profile.members.reject { |m| Profile::TCP.public_send(m) == Profile::QUIC.public_send(m) }
    assert_equal Profile.members, differences, "every flag exists because QUIC differs"

    assert_equal [true, false], [Profile::TCP.record_layer, Profile::QUIC.record_layer]
    assert_equal [true, false], [Profile::TCP.compatibility_mode, Profile::QUIC.compatibility_mode]
    assert_equal [false, true], [Profile::TCP.reject_nonempty_session_id, Profile::QUIC.reject_nonempty_session_id]
    assert_equal [true, false], [Profile::TCP.send_end_of_early_data, Profile::QUIC.send_end_of_early_data]
    assert_equal [true, false], [Profile::TCP.allow_key_update_message, Profile::QUIC.allow_key_update_message]
    assert_equal [[], [0x39]], [Profile::TCP.required_extensions, Profile::QUIC.required_extensions]
    assert_equal [[0x39], []], [Profile::TCP.forbidden_extensions, Profile::QUIC.forbidden_extensions]
    assert_equal %i[free sentinel], [Profile::TCP.max_early_data_size_policy, Profile::QUIC.max_early_data_size_policy]
    assert_equal [[], [:TLS_AES_128_CCM_8_SHA256]],
      [Profile::TCP.never_select_cipher_suites, Profile::QUIC.never_select_cipher_suites]
    assert_equal [false, true], [Profile::TCP.all_alerts_fatal, Profile::QUIC.all_alerts_fatal]
  end

  def test_protocol_violation_reasons
    assert_empty Profile::TCP.protocol_violation_reasons
    assert_equal %i[handshake_data_spans_key_change wrong_epoch post_handshake_certificate_request
      max_early_data_size_not_sentinel nonempty_legacy_session_id], Profile::QUIC.protocol_violation_reasons
  end

  def test_profiles_are_shareable
    assert Ractor.shareable?(Profile::TCP)
    assert Ractor.shareable?(Profile::QUIC)
  end
end
