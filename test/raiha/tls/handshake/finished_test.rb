require "test_helper"
require "raiha/tls/test"

class RaihaNextTLSHandshakeFinishedTest < Minitest::Test
  TLS = Raiha::TLS
  RFC8448 = TLS::Test::RFC8448::Simple1RTT
  REGISTRY = TLS::Extension::Registry::BUILTIN

  def test_parse_and_encode_rfc8448
    [RFC8448::SERVER_FINISHED, RFC8448::CLIENT_FINISHED].each do |bytes|
      finished = TLS::Handshake.parse(bytes, registry: REGISTRY)
      assert_instance_of TLS::Handshake::Finished, finished
      assert_equal 20, finished.msg_type
      assert_equal bytes.byteslice(4..), finished.verify_data
      assert_equal_bin bytes, finished.encode
      assert Ractor.shareable?(finished)
    end
  end

  # The length depends on the negotiated hash, which only the state machine
  # knows, so any length parses here.
  def test_any_length_parses
    assert_equal "".b, TLS::Handshake.parse("\x14\x00\x00\x00".b, registry: REGISTRY).verify_data
    assert_equal 48, TLS::Handshake.parse("\x14\x00\x00\x30".b + "\x00".b * 48, registry: REGISTRY).verify_data.bytesize
  end

  def test_inspect_masks_verify_data
    finished = TLS::Handshake.parse(RFC8448::SERVER_FINISHED, registry: REGISTRY)
    assert_equal "#<data Raiha::TLS::Handshake::Finished verify_data=[32 bytes]>", finished.inspect
  end
end
