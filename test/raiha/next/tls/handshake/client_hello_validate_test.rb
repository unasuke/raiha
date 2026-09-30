require "raiha/next/test_helper"
require "raiha/next/tls/test"

# Each row of the ClientHello table gets two tests: the violation alone, and
# the violation together with one from an earlier row, which must win. The
# second kind catches a reordering of the checks.
class RaihaNextTLSHandshakeClientHelloValidateTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Extension = TLS::Extension
  Violation = TLS::Handshake::Violation
  RFC8448 = TLS::Test::RFC8448
  REGISTRY = Extension::Registry::BUILTIN

  # Full handshake: supported_groups, key_share, signature_algorithms, no PSK.
  FULL = TLS::Handshake.parse(RFC8448::Simple1RTT::CLIENT_HELLO, registry: REGISTRY)
  # Resumption: pre_shared_key (last) and psk_key_exchange_modes as well.
  PSK = TLS::Handshake.parse(RFC8448::Resumed0RTT::CLIENT_HELLO, registry: REGISTRY)

  def remove(ch, type) = ch.with(extensions: ch.extensions.reject { |ext| ext.extension_type == type })

  def replace(ch, ext) = ch.with(extensions: ch.extensions.map { |e| e.extension_type == ext.extension_type ? ext : e })

  def violation(alert, reason) = Violation.new(alert:, reason:)

  def key_share(*groups)
    Extension::KeyShare::CH.new(client_shares: groups.map { |g| Extension::KeyShare::Entry.new(group: g, key_exchange: "k".b) })
  end

  # Row mutations, each producing that row's violation from a valid ClientHello.
  def row1(ch) = ch.with(legacy_version: 0x0301)
  def row2(ch) = replace(ch, Extension::SupportedVersions::CH.new(versions: [0x0303, 0x0302]))
  def row3(ch) = ch.with(legacy_compression_methods: [1, 0])
  def row4(ch) = remove(ch, Extension::SignatureAlgorithms::TYPE)
  def row5(ch) = remove(ch, Extension::KeyShare::TYPE)
  def row6(ch) = remove(ch, Extension::PskKeyExchangeModes::TYPE)
  def row7(ch) = replace(ch, Extension::SupportedGroups.new(named_group_list: [0x001d, 0x001d, 0x0017]))
  def row8(ch) = replace(ch, key_share(0x001d, 0x001d))
  def row9(ch) = replace(ch, key_share(0x001e))

  def row10(ch)
    psk = ch.extension(Extension::PreSharedKey::TYPE)
    ch.with(extensions: [psk] + ch.extensions.reject { |ext| ext.equal?(psk) })
  end

  def row11(ch)
    psk = ch.extension(Extension::PreSharedKey::TYPE)
    replace(ch, psk.with(binders: psk.binders * 2))
  end

  def test_valid_client_hellos
    assert_nil FULL.validate
    assert_nil PSK.validate
  end

  def test_row1_legacy_version
    assert_equal violation(:protocol_version, :legacy_version), row1(FULL).validate
  end

  def test_row2_supported_versions_without_tls13
    assert_equal violation(:protocol_version, :supported_versions), row2(FULL).validate
    assert_equal violation(:protocol_version, :supported_versions), remove(FULL, Extension::SupportedVersions::TYPE).validate
  end

  def test_row2_after_row1
    assert_equal violation(:protocol_version, :legacy_version), row2(row1(FULL)).validate
  end

  def test_row3_compression
    assert_equal violation(:illegal_parameter, :legacy_compression_methods), row3(FULL).validate
  end

  def test_row3_after_row2
    assert_equal violation(:protocol_version, :supported_versions), row3(row2(FULL)).validate
  end

  def test_row4_missing_signature_algorithms_or_supported_groups_without_psk
    assert_equal violation(:missing_extension, :signature_algorithms), row4(FULL).validate
    no_groups = remove(remove(FULL, Extension::SupportedGroups::TYPE), Extension::KeyShare::TYPE)
    assert_equal violation(:missing_extension, :supported_groups), no_groups.validate
  end

  def test_row4_does_not_apply_with_psk
    assert_nil row4(PSK).validate
  end

  def test_row4_after_row3
    assert_equal violation(:illegal_parameter, :legacy_compression_methods), row4(row3(FULL)).validate
  end

  # A ClientHello without supported_versions is not a TLS 1.3 one, so the
  # TLS 1.3 extension requirements must not be what rejects it.
  def test_row4_after_row2
    no_versions = remove(FULL, Extension::SupportedVersions::TYPE)
    assert_equal violation(:protocol_version, :supported_versions), row4(no_versions).validate
    assert_equal violation(:protocol_version, :supported_versions), row6(row5(remove(PSK, Extension::SupportedVersions::TYPE))).validate
  end

  def test_row5_only_one_of_supported_groups_and_key_share
    assert_equal violation(:missing_extension, :supported_groups_without_key_share), row5(PSK).validate
    assert_equal violation(:missing_extension, :key_share_without_supported_groups),
      remove(PSK, Extension::SupportedGroups::TYPE).validate
  end

  def test_row5_after_row4
    assert_equal violation(:missing_extension, :signature_algorithms), row5(row4(FULL)).validate
  end

  def test_row6_psk_without_modes
    assert_equal violation(:missing_extension, :psk_key_exchange_modes), row6(PSK).validate
  end

  def test_row6_after_row5
    assert_equal violation(:missing_extension, :supported_groups_without_key_share), row6(row5(PSK)).validate
  end

  def test_row7_duplicate_supported_group
    assert_equal violation(:illegal_parameter, :duplicate_supported_group), row7(FULL).validate
  end

  def test_row7_after_row6
    assert_equal violation(:missing_extension, :psk_key_exchange_modes), row7(row6(PSK)).validate
  end

  def test_row8_duplicate_key_share_group
    assert_equal violation(:illegal_parameter, :duplicate_key_share_group), row8(FULL).validate
  end

  def test_row8_after_row7
    assert_equal violation(:illegal_parameter, :duplicate_supported_group), row8(row7(FULL)).validate
  end

  def test_row9_key_share_group_not_in_supported_groups
    assert_equal violation(:illegal_parameter, :key_share_group_not_supported), row9(FULL).validate
  end

  def test_row9_lets_grease_through
    groups = Extension::SupportedGroups.new(named_group_list: [0x0a0a, 0x001d])
    assert_nil replace(replace(FULL, groups), key_share(0x0a0a, 0x001d)).validate
  end

  def test_row9_after_row8
    assert_equal violation(:illegal_parameter, :duplicate_key_share_group), replace(FULL, key_share(0x001e, 0x001e)).validate
  end

  def test_row10_pre_shared_key_not_last
    assert_equal violation(:illegal_parameter, :pre_shared_key_not_last), row10(PSK).validate
  end

  def test_row10_after_row9
    assert_equal violation(:illegal_parameter, :key_share_group_not_supported), row10(row9(PSK)).validate
  end

  def test_row11_binders_count
    assert_equal violation(:illegal_parameter, :binders_count), row11(PSK).validate
  end

  def test_row11_after_row10
    assert_equal violation(:illegal_parameter, :pre_shared_key_not_last), row10(row11(PSK)).validate
  end
end
