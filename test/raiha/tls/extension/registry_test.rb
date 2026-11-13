require "test_helper"
require "raiha/tls"

class RaihaNextTLSExtensionRegistryTest < Minitest::Test
  Extension = Raiha::TLS::Extension
  Registry = Extension::Registry

  # The extensions this implementation knows and the messages RFC 9846 (and
  # RFC 8449 and RFC 8879 for record_size_limit and compress_certificate)
  # allows them in. HelloRetryRequest and CertificateEntry are separate
  # contexts.
  EXPECTED_PLACEMENT = {
    0 => %i[client_hello encrypted_extensions],
    5 => %i[client_hello certificate_request certificate_entry],
    10 => %i[client_hello encrypted_extensions],
    13 => %i[client_hello certificate_request],
    16 => %i[client_hello encrypted_extensions],
    18 => %i[client_hello certificate_request certificate_entry],
    27 => %i[client_hello certificate_request],
    28 => %i[client_hello encrypted_extensions],
    41 => %i[client_hello server_hello],
    42 => %i[client_hello encrypted_extensions new_session_ticket],
    43 => %i[client_hello server_hello hello_retry_request],
    44 => %i[client_hello hello_retry_request],
    45 => %i[client_hello],
    47 => %i[client_hello certificate_request],
    49 => %i[client_hello],
    50 => %i[client_hello certificate_request],
    51 => %i[client_hello server_hello hello_retry_request]
  }.freeze

  module TransportParameters
    TYPE = 57

    class Value < Data.define(:data)
      def self.parse(data) = new(data:)

      def extension_type = TYPE

      def encode = data
    end

    CODECS = { client_hello: Value, encrypted_extensions: Value }.freeze
  end

  def test_placement_follows_the_rfc_table
    assert_equal EXPECTED_PLACEMENT, Extension::PLACEMENT.transform_values(&:keys)
  end

  def test_status_request_v2_is_not_registered
    refute Registry::BUILTIN.registered?(17)
  end

  def test_lookup
    assert_equal Extension::KeyShare::HRR, Registry::BUILTIN.lookup(51, :hello_retry_request)
    assert_equal Extension::SupportedVersions::SH, Registry::BUILTIN.lookup(43, :hello_retry_request)
    assert_nil Registry::BUILTIN.lookup(51, :encrypted_extensions)
    assert_nil Registry::BUILTIN.lookup(0xff01, :client_hello)
  end

  def test_known_but_uninterpreted_extensions_parse_to_opaque
    parser = Registry::BUILTIN.lookup(18, :client_hello)
    assert_equal Extension::Opaque.new(type: 18, data: "".b), parser.parse("".b)
  end

  def test_builtin_is_shareable
    assert Ractor.shareable?(Registry::BUILTIN)
  end

  def test_with_adds_an_extension_the_same_way_as_the_builtin_ones
    registry = Registry::BUILTIN.with(TransportParameters)
    assert registry.registered?(57)
    assert_equal TransportParameters::Value, registry.lookup(57, :encrypted_extensions)
    assert_nil registry.lookup(57, :server_hello)
    assert Ractor.shareable?(registry)
    refute Registry::BUILTIN.registered?(57)
  end

  def test_with_does_not_freeze_the_callers_hash
    codecs = { client_hello: TransportParameters::Value }
    mod = Module.new
    mod.const_set(:TYPE, 58)
    mod.const_set(:CODECS, codecs)
    registry = Registry::BUILTIN.with(mod)
    refute codecs.frozen?
    assert Ractor.shareable?(registry)
  end

  def test_with_rejects_a_type_already_registered
    registry = Registry::BUILTIN.with(TransportParameters)
    assert_raises(ArgumentError) { registry.with(TransportParameters) }
    assert_raises(ArgumentError) { Registry::BUILTIN.with(TransportParameters, TransportParameters) }

    key_share = Module.new
    key_share.const_set(:TYPE, 51)
    key_share.const_set(:CODECS, { client_hello: TransportParameters::Value }.freeze)
    assert_raises(ArgumentError) { Registry::BUILTIN.with(key_share) }
  end

  def test_with_rejects_malformed_modules
    bad_context = Module.new
    bad_context.const_set(:TYPE, 58)
    bad_context.const_set(:CODECS, { finished: TransportParameters::Value }.freeze)
    assert_raises(ArgumentError) { Registry::BUILTIN.with(bad_context) }

    bad_type = Module.new
    bad_type.const_set(:TYPE, 0x10000)
    bad_type.const_set(:CODECS, {}.freeze)
    assert_raises(ArgumentError) { Registry::BUILTIN.with(bad_type) }
  end

  def test_with_rejects_a_codec_that_cannot_be_shared
    parser = Object.new
    parser.instance_variable_set(:@hook, proc { nil })
    def parser.parse(data) = data
    unshareable = Module.new
    unshareable.const_set(:TYPE, 58)
    unshareable.const_set(:CODECS, { client_hello: parser })
    assert_raises(ArgumentError) { Registry::BUILTIN.with(unshareable) }
  end
end
