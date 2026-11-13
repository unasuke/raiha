require "raiha/next/test_helper"
require "raiha/next/tls/test"

# Each row of the ServerHello table gets two tests, as for the ClientHello.
class RaihaNextTLSHandshakeServerHelloValidateTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Extension = TLS::Extension
  Violation = TLS::Handshake::Violation
  RFC8448 = TLS::Test::RFC8448
  REGISTRY = Extension::Registry::BUILTIN

  SH = TLS::Handshake.parse(RFC8448::Simple1RTT::SERVER_HELLO, registry: REGISTRY)
  HRR = TLS::Handshake.parse(RFC8448::HelloRetryRequest::HELLO_RETRY_REQUEST, registry: REGISTRY)

  def violation(alert, reason) = Violation.new(alert:, reason:)

  def without_versions(sh) = sh.with(extensions: sh.extensions.reject { |ext| ext.extension_type == 43 })

  def with_sentinel(sh, last_byte) = sh.with(random: sh.random.byteslice(0, 24) + "DOWNGRD".b + last_byte.chr.b)

  def row1(sh) = sh.with(legacy_version: 0x0302)
  def row2(sh) = sh.with(legacy_compression_method: 1)
  def row3(sh) = with_sentinel(without_versions(sh), 1)
  def row4(sh) = without_versions(sh)

  def row5(sh)
    sh.with(extensions: sh.extensions.map { |ext| ext.extension_type == 43 ? Extension::SupportedVersions::SH.new(selected_version: 0x0303) : ext })
  end

  def test_valid_server_hello_and_hello_retry_request
    assert_nil SH.validate
    assert_nil HRR.validate
  end

  # With supported_versions, legacy_version is ignored (RFC 8446
  # "Supported Versions").
  def test_row1_legacy_version
    assert_equal violation(:protocol_version, :legacy_version), row1(without_versions(SH)).validate
    assert_nil row1(SH).validate
    assert_nil row1(HRR).validate
  end

  def test_row2_compression
    assert_equal violation(:illegal_parameter, :legacy_compression_method), row2(SH).validate
  end

  def test_row2_with_legacy_version_ignored
    assert_equal violation(:illegal_parameter, :legacy_compression_method), row2(row1(SH)).validate
  end

  def test_row3_downgrade_sentinel
    assert_equal violation(:illegal_parameter, :downgrade_sentinel), row3(SH).validate
    assert_equal violation(:illegal_parameter, :downgrade_sentinel), with_sentinel(without_versions(SH), 0).validate
  end

  def test_row3_after_row2
    assert_equal violation(:illegal_parameter, :legacy_compression_method), row3(row2(SH)).validate
  end

  def test_sentinel_is_ignored_when_supported_versions_is_present
    assert_nil with_sentinel(SH, 1).validate
  end

  def test_row4_missing_supported_versions
    assert_equal violation(:protocol_version, :supported_versions), row4(SH).validate
  end

  def test_row4_after_row2
    assert_equal violation(:illegal_parameter, :legacy_compression_method), row4(row2(SH)).validate
  end

  def test_row5_selected_version
    assert_equal violation(:illegal_parameter, :selected_version), row5(SH).validate
    assert_equal violation(:illegal_parameter, :selected_version), row5(HRR).validate
  end

  def test_row5_after_row2
    assert_equal violation(:illegal_parameter, :legacy_compression_method), row5(row2(SH)).validate
  end
end
