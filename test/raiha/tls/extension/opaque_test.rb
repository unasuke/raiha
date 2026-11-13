require "test_helper"
require "raiha/tls"

class RaihaNextTLSExtensionOpaqueTest < Minitest::Test
  Extension = Raiha::TLS::Extension

  def test_keeps_the_type_and_raw_data
    ext = Extension::Opaque.new(type: 0xff01, data: "\x00".b)
    assert_equal 0xff01, ext.extension_type
    assert_equal_bin "\x00".b, ext.encode
  end

  def test_data_is_never_inspected
    ext = Extension::Opaque.new(type: 0x1234, data: "\xff\xff\xff".b)
    assert_equal_bin "\xff\xff\xff".b, ext.encode
  end
end
