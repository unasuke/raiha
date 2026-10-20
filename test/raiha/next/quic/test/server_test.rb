require "raiha/next/test_helper"
require "raiha/next/quic/test"
require "raiha/next/support/quic_pair"

# Handshakes on a Test::Network, the client a Connection and the server an
# Endpoint that takes every offer, over paths that lose, reorder and delay.
class RaihaNextQUICTestServerTest < Minitest::Test
  include NextQUICPair

  Test = QUIC::Test

  # A network with a client and a server on it, linked by `model` both
  # ways or by `forward` and `reverse`; the network, the client and the
  # server.
  def network(seed: 1, model: nil, forward: model, reverse: model, **server)
    net = Test::Network.new(seed:)
    client = net.add(client_connection(random: Random.new(seed)), address: CLIENT)
    tls_config = server_config
    keyring = TLS::Keyring.server(config: tls_config, identities: [NextTLSPair.server_identity], random: Random.new(seed + 1))
    host = net.add_server(config: QUIC::Config.new, tls_config:, keyring:, time: NOW, address: SERVER, **server)
    net.link(client, host, forward:, reverse:)
    [net, client, host]
  end

  def handshaken?(client, host) = client.handshake_confirmed? && host.connections.any?(&:handshake_confirmed?)

  def test_a_handshake_on_a_network
    net, client, host = network
    assert net.run_until { handshaken?(client, host) }
    assert_equal 1, host.connections.size
    assert_in_delta 0.0, net.now, 0.001
  end

  def test_a_handshake_through_a_bottleneck
    model = Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.025, queue: 100_000)
    net, client, host = network(model:)
    assert net.run_until { handshaken?(client, host) }
    assert_operator net.now, :>=, 0.1
  end

  # Datagrams lost, a tenth of them each way, on twenty seeds.
  def test_handshakes_over_loss
    20.times do |seed|
      net, client, host = network(seed:, model: [Test::RandomLoss.new(rate: 0.1), Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.01, queue: 100_000)])
      assert net.run_until { handshaken?(client, host) }, "seed #{seed}"
    end
  end

  def test_handshakes_over_reordering
    20.times do |seed|
      net, client, host = network(seed:, model: [Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.01, queue: 100_000), Test::Reorder.new(rate: 0.3)])
      assert net.run_until { handshaken?(client, host) }, "seed #{seed}"
    end
  end

  # A server that answers an offer of an address not validated with a
  # Retry.
  def test_a_handshake_after_a_retry
    net, client, host = network(retry_unvalidated: true, model: Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.01, queue: 100_000))
    assert net.run_until { handshaken?(client, host) }
    assert_nil client.close_reason
  end
end
