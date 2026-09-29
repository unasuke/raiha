require "raiha/next/test_helper"
require "raiha/next/tls/test"

class RaihaNextTLSExtensionListTest < Minitest::Test
  Codec = Raiha::Next::TLS::Codec
  Extension = Raiha::Next::TLS::Extension
  Registry = Extension::Registry
  RFC8448 = Raiha::Next::TLS::Test::RFC8448::Simple1RTT

  # The extension block of the RFC 8448 section 3 ClientHello: after the
  # header, version, random, empty session id, three suites and one
  # compression method.
  CH_EXTENSIONS = RFC8448::CLIENT_HELLO.byteslice(49..)

  def read(bytes, context, registry = Registry::BUILTIN)
    r = Codec::Reader.new(bytes)
    list = Extension.read_list(r, context:, registry:)
    r.finish!
    list
  end

  def block(*extensions)
    body = extensions.map { |type, data| [type, data.bytesize].pack("nn") + data }.join.b
    [body.bytesize].pack("n") + body
  end

  def test_reads_the_rfc8448_client_hello_block
    list = read(CH_EXTENSIONS, :client_hello)
    assert_equal [0, 0xff01, 10, 35, 51, 43, 13, 45, 28], list.map(&:extension_type)
    assert_equal "server", list[0].host_name
    assert_equal Extension::Opaque.new(type: 0xff01, data: "\x00".b), list[1]
    assert_equal Extension::Opaque.new(type: 35, data: "".b), list[3]
    assert_instance_of Extension::KeyShare::CH, list[4]
    assert list.frozen?
    assert Ractor.shareable?(list)
  end

  def test_write_list_restores_the_bytes
    w = Codec::Writer.new
    Extension.write_list(w, read(CH_EXTENSIONS, :client_hello))
    assert_equal_bin CH_EXTENSIONS, w.to_s
  end

  def test_duplicate_type
    assert_raises(Codec::Duplicate) { read(block([43, "\x02\x03\x04".b], [43, "\x02\x03\x04".b]), :client_hello) }
  end

  def test_duplicate_unknown_type
    assert_raises(Codec::Duplicate) { read(block([0x1234, "".b], [0x1234, "".b]), :client_hello) }
  end

  def test_known_type_in_a_message_it_may_not_appear_in
    error = assert_raises(Codec::IllegalPlacement) { read(block([51, "\x00\x17".b]), :encrypted_extensions) }
    assert_equal :illegal_parameter, error.alert
  end

  def test_unknown_type_is_kept_whatever_it_contains
    list = read(block([0x1234, "\xff\xff\xff".b]), :encrypted_extensions)
    assert_equal [Extension::Opaque.new(type: 0x1234, data: "\xff\xff\xff".b)], list
  end

  def test_known_type_with_trailing_data
    assert_raises(Codec::TrailingData) { read(block([43, "\x03\x04\x00".b]), :server_hello) }
  end

  def test_minimum_length
    r = Codec::Reader.new("\x00\x00".b)
    assert_raises(Codec::RangeViolation) { Extension.read_list(r, context: :server_hello, registry: Registry::BUILTIN, min: 6) }
  end

  def test_write_list_rejects_a_duplicate_type
    ext = Extension::SupportedVersions::SH.new(selected_version: 0x0304)
    assert_raises(Codec::EncodeError) { Extension.write_list(Codec::Writer.new, [ext, ext]) }
  end

  def test_write_list_checks_the_minimum_length
    assert_raises(Codec::EncodeError) { Extension.write_list(Codec::Writer.new, [], min: 6) }
  end
end
