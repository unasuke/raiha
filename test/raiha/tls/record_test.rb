require "test_helper"
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
end
