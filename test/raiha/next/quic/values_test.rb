require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICValuesTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  TLS = Raiha::Next::TLS

  # RFC 9000 "Transport Error Codes".
  def test_error_codes
    codes = QUIC::ErrorCode.constants.reject { |name| name == :CRYPTO_ERROR_BASE }.to_h { |name| [name, QUIC::ErrorCode.const_get(name)] }
    assert_equal (0x00..0x10).to_a, codes.values.sort
    assert_equal 0x0a, QUIC::ErrorCode::PROTOCOL_VIOLATION
    assert_equal 0x0128, QUIC::ErrorCode.crypto_error(TLS::IANA.alert_code(:handshake_failure))
    assert_raises(ArgumentError) { QUIC::ErrorCode.crypto_error(256) }
  end

  def test_errors_are_misuse
    assert_operator QUIC::Error::StateError, :<, QUIC::Error::Usage
    assert_operator QUIC::Error::StreamError, :<, QUIC::Error::Usage
    assert_operator QUIC::Error::Usage, :<, QUIC::Error::Base
  end

  # What the peer broke is raised inside the layer with the error to close
  # with; a frame that does not decode is one such.
  def test_violations
    assert_equal [QUIC::ErrorCode::PROTOCOL_VIOLATION, nil], QUIC::Violation.new("x").then { [_1.code, _1.frame_type] }
    assert_operator QUIC::Wire::Malformed, :<, QUIC::Violation
    assert_equal QUIC::ErrorCode::FRAME_ENCODING_ERROR, QUIC::Wire::Malformed.new("x").code
    refute_operator QUIC::Violation, :<, QUIC::Error::Base
  end

  # A connection closed under a waiting call is no misuse, and the error it
  # closed with comes along whole, as a Data cannot be an exception's cause.
  def test_closed_errors
    by_peer = QUIC::ConnectionError.new(code: QUIC::ErrorCode::PROTOCOL_VIOLATION, frame_type: 0x07, reason: "NEW_TOKEN from a client",
      application: false)
    closed = QUIC::ClosedError.new(by_peer)
    assert_same by_peer, closed.error
    assert_equal "closed with transport error 0xa: NEW_TOKEN from a client", closed.message
    assert_equal "closed with application error 0x100",
      QUIC::ClosedError.new(QUIC::ConnectionError.new(code: 0x100, frame_type: nil, reason: "", application: true)).message
    refute_operator QUIC::ClosedError, :<, QUIC::Error::Base
  end

  def test_values_are_shareable_once_frozen
    # Without certificates: an OpenSSL::X509::Certificate is never shareable.
    handshake = Ractor.make_shareable(TLS::Event::HandshakeComplete.new(server_name: "localhost", alpn: "h3",
      cipher_suite: :TLS_AES_128_GCM_SHA256, group: :x25519, resumed: false, early_data_accepted: false,
      peer_certificates: [], peer_verified: true))
    error = QUIC::ConnectionError.new(code: QUIC::ErrorCode::NO_ERROR, frame_type: nil, reason: "".freeze, application: false)
    values = [
      error,
      QUIC::Transmit.new(payload: "x".b.freeze, destination: Ractor.make_shareable(["192.0.2.1", 443]), source: nil, ecn: :not_ect, segment_size: nil),
      QUIC::Event::Connected.new(handshake:),
      QUIC::Event::StreamReadable.new(stream_id: 0),
      QUIC::Event::StreamWritable.new(stream_id: 4),
      QUIC::Event::StreamReset.new(stream_id: 0, error_code: 1, final_size: 10),
      QUIC::Event::StopSending.new(stream_id: 0, error_code: 1),
      QUIC::Event::DatagramReceived.new(data: "d".b.freeze),
      QUIC::Event::KeyUpdated.new(phase: 1),
      QUIC::Event::TLSEvent.new(event: TLS::Event::SessionNotOffered.new(reason: :ticket_expired)),
      QUIC::Event::Closed.new(error:, by_peer: true)
    ]
    values.each { |value| assert Ractor.shareable?(value), value.class.name }
  end

  def test_events_match_by_pattern
    case QUIC::Event::StreamReset.new(stream_id: 4, error_code: 7, final_size: 100)
    in QUIC::Event::StreamReset(stream_id:, final_size:)
      assert_equal [4, 100], [stream_id, final_size]
    end
  end
end
