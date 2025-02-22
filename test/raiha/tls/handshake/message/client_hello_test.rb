require "test_helper"
# require "raiha/tls/handshake/message/client_hello" # TODO: CipherSuite
require "raiha/tls/handshake"

class RaihaTLSHandshakeClientHelloTest < Minitest::Test
  def test_build
    ch = Raiha::TLS::Handshake::ClientHello.build
    assert_equal Raiha::TLS::Handshake::ClientHello, ch.class
    assert_equal 1, ch.cipher_suites.length
    assert_equal 0x00, ch.legacy_session_id
  end

  def test_serialize
    ch = Raiha::TLS::Handshake::ClientHello.build
    assert_equal String, ch.serialize.class
    # assert_equal "\x00\x00", ch.byteslice(0..1) # TODO: ruby 3.4
  end

  def test_deserialize
    serialized = Raiha::TLS::Handshake::ClientHello.build.serialize
    deserialized = Raiha::TLS::Handshake::ClientHello.deserialize(serialized)
    assert_equal Raiha::TLS::Handshake::ClientHello, deserialized.class
    assert_equal 1, deserialized.cipher_suites.length
    assert_equal "", deserialized.legacy_session_id
  end

  def test_extensions_for_client_hello
    exts = Raiha::TLS::Handshake::ClientHello.new.extensions_for_client_hello
    assert_equal 3, exts.length
  end

  def test_serialize_cipher_suites
    # TODO: move to abstract class?
    ch = Raiha::TLS::Handshake::ClientHello.build
    serialized = ch.serialize_cipher_suites
    assert_equal String, serialized.class
  end

  def test_serialize_extensions
    # TODO: move to abstract class?
    ch = Raiha::TLS::Handshake::ClientHello.build
    serialized = ch.serialize_extensions
    assert_equal String, serialized.class
  end
end
