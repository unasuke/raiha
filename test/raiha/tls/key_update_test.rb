require "test_helper"
require_relative "../../../lib/raiha/tls/handshake"

class RaihaTLSKeyUpdateTest < Minitest::Test
  def test_deserialize_update_not_requested
    key_update = Raiha::TLS::Handshake::KeyUpdate.deserialize("\x00")
    assert_equal :update_not_requested, key_update.request_update
  end

  def test_deserialize_update_requested
    key_update = Raiha::TLS::Handshake::KeyUpdate.deserialize("\x01")
    assert_equal :update_requested, key_update.request_update
  end

  def test_serialize_update_not_requested
    key_update = Raiha::TLS::Handshake::KeyUpdate.new
    key_update.request_update = :update_not_requested
    assert_equal "\x00", key_update.serialize
  end

  def test_serialize_update_requested
    key_update = Raiha::TLS::Handshake::KeyUpdate.new
    key_update.request_update = :update_requested
    assert_equal "\x01", key_update.serialize
  end

  def test_roundtrip_via_handshake
    key_update = Raiha::TLS::Handshake::KeyUpdate.new
    key_update.request_update = :update_requested

    hs = Raiha::TLS::Handshake.new
    hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:key_update]
    hs.message = key_update

    serialized = hs.serialize
    deserialized = Raiha::TLS::Handshake.deserialize(serialized)

    assert_equal Raiha::TLS::Handshake::KeyUpdate, deserialized.message.class
    assert_equal :update_requested, deserialized.message.request_update
  end

  def test_default_is_update_not_requested
    key_update = Raiha::TLS::Handshake::KeyUpdate.new
    assert_equal :update_not_requested, key_update.request_update
  end
end
