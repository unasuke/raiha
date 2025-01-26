require "test_helper"
require "raiha/tls/handshake"
require "raiha/tls/record"

class RaihaTLSRecordTest < Minitest::Test
  def test_tlsplaintext_serialize
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
    end
    record = Raiha::TLS::Record::TLSPlaintext.serialize(handshake)
    assert_equal 1, record.size
  end

  def test_tlsplaintext_serialize_require_fragment
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
      hs.message.extensions << Raiha::TLS::Handshake::Extension::Padding.generate_padding_with_length(16384)
    end
    record = Raiha::TLS::Record::TLSPlaintext.serialize(handshake)
    assert_equal 2, record.size
    assert_equal 16389, record[0].bytesize # limit of single TLSPlaintext struct
  end

  def test_tlsplaintext_unwrap_fragment
    # normal case
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
    end
    record = Raiha::TLS::Record::TLSPlaintext.serialize(handshake)
    fragment = Raiha::TLS::Record::TLSPlaintext.unwrap_fragment(record[0])
    assert_equal String, fragment[:fragment].class

    # fragment size is too large
    assert_raises(RuntimeError) do
      fragment = Raiha::TLS::Record::TLSPlaintext.unwrap_fragment(record[0] + "\x00")
    end

    # fragment size is too short
    assert_raises(RuntimeError) do
      fragment = Raiha::TLS::Record::TLSPlaintext.unwrap_fragment(record[0][0..-2])
    end
  end

  def test_tlsplaintext_deserialize
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
    end
    record = Raiha::TLS::Record::TLSPlaintext.serialize(handshake)
    deserialized = Raiha::TLS::Record::TLSPlaintext.deserialize(record)
    assert_equal 1, deserialized.length

    handshake2 = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
    end
    record2 = Raiha::TLS::Record::TLSPlaintext.serialize(handshake2)
    deserialized2 = Raiha::TLS::Record::TLSPlaintext.deserialize(record + record2)
    assert_equal 2, deserialized2.length
    assert_equal Raiha::TLS::Handshake, deserialized2[0].class
    assert_equal Raiha::TLS::Handshake, deserialized2[1].class
  end

  def test_tlsplaintext_deserialize_fragmented_handshake
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Handshake::ClientHello.build
      hs.message.extensions << Raiha::TLS::Handshake::Extension::Padding.generate_padding_with_length(16384)
    end
    record = Raiha::TLS::Record::TLSPlaintext.serialize(handshake)
    deserialized = Raiha::TLS::Record::TLSPlaintext.deserialize(record)
    assert_equal 1, deserialized.length
    assert_equal Raiha::TLS::Handshake, deserialized[0].class
  end
end
