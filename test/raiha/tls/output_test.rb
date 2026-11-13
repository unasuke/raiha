require "test_helper"
require "raiha/tls"

class RaihaNextTLSOutputTest < Minitest::Test
  TLS = Raiha::TLS
  SUITE = TLS::CipherSuite::TLS_AES_128_GCM_SHA256

  def test_secret_hides_the_secret_from_inspect
    secret = TLS::Output::Secret.new(epoch: :handshake, direction: :read, secret: "\xAA".b * 32, cipher_suite: SUITE)
    refute_includes secret.inspect, "\\xAA"
    assert_includes secret.inspect, "secret=[32 bytes]"
    assert_includes secret.inspect, "epoch=:handshake"
  end

  def test_outputs_are_shareable_once_frozen
    outputs = [
      TLS::Output::Message.new(epoch: :initial, bytes: "\x01\x00\x00\x00".b.freeze),
      TLS::Output::Secret.new(epoch: :application, direction: :write, secret: ("\x00".b * 32).freeze, cipher_suite: SUITE),
      TLS::Output::Alert.new(level: :fatal, description: :decode_error, epoch: :handshake)
    ]
    outputs.each { |output| assert Ractor.shareable?(output), output.class.name }
  end
end
