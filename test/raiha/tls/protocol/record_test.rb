require "test_helper"
require "raiha/tls/protocol/record"

class RaihaProtocolsRecordTest < Minitest::Test
  def test_tlsplaintext_serialize
    handshake = Raiha::TLS::Protocol::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Protocol::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Protocol::Handshake::ClientHello.build
    end
    record = Raiha::TLS::Protocol::Record::TLSPlaintext.serialize(handshake)
    assert_equal 1, record.size
  end

  def test_tlsplaintext_serialize_require_fragment
    handshake = Raiha::TLS::Protocol::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Protocol::Handshake::HANDSHAKE_TYPE[:client_hello]
      hs.message = Raiha::TLS::Protocol::Handshake::ClientHello.build
      hs.message.extensions << Raiha::TLS::Protocol::Handshake::Extension::Padding.generate_padding_with_length(16384)
    end
    record = Raiha::TLS::Protocol::Record::TLSPlaintext.serialize(handshake)
    assert_equal 2, record.size
    assert_equal 16389, record[0].bytesize # limit of single TLSPlaintext struct
  end
end
