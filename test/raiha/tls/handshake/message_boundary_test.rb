require "test_helper"
require "support/tls_pair"

# Handshake messages split across inputs, several in one input, and the
# size limits per message type, decided from the header alone.
class RaihaTLSMessageBoundaryTest < Minitest::Test
  TLS = Raiha::TLS
  Pair = TLSPair
  NOW = Pair::NOW

  def server_flight
    client = Pair.client
    server = Pair.server(client.outputs.first.bytes)
    [client, server, server.outputs.grep(TLS::Output::Message)]
  end

  def test_messages_split_anywhere
    client, server, flight = server_flight
    flight.each do |message|
      message.bytes.each_char { |byte| client.receive(byte, epoch: message.epoch, now: NOW) }
    end
    Pair.deliver(client.outputs, server)
    assert client.complete?
    assert server.complete?
  end

  def test_one_epoch_in_one_input
    client, _, flight = server_flight
    flight.group_by(&:epoch).each { |epoch, messages| client.receive(messages.map(&:bytes).join, epoch:, now: NOW) }
    assert client.complete?
  end

  # The header alone decides: no body is waited for.
  def test_size_limits_per_type
    # Before the header: nothing for EncryptedExtensions, the
    # EncryptedExtensions for a Certificate.
    { 8 => [(16 * 1024) + 1, 0], 11 => [(256 * 1024) + 1, 1] }.each do |type, (length, before)|
      client, _, flight = server_flight
      client.receive(flight.first.bytes, epoch: :initial, now: NOW)
      header = [type].pack("C") + [length].pack("N").byteslice(1, 3)
      client.receive(flight[1, before].map(&:bytes).join + header, epoch: :handshake, now: NOW)
      assert_equal :decode_error, client.alert, type
      assert_equal :message_too_large, client.each_event.grep(TLS::Event::Failed).first.reason
    end
  end

  # A Certificate may be larger than other messages.
  def test_certificate_limit_is_larger
    client, _, flight = server_flight
    client.receive(flight.first.bytes, epoch: :initial, now: NOW)
    client.receive(flight[1].bytes + "\x0b\x01\x00\x00".b, epoch: :handshake, now: NOW)
    refute client.failed?
  end
end
