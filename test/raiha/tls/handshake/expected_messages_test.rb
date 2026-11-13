require "test_helper"
require "support/tls_pair"

# The tables of expected messages, checked against the states and against a
# Machine in each state: every handshake type a state does not expect,
# unknown types 0 and 255 included, fails with unexpected_message.
class RaihaNextTLSExpectedMessagesTest < Minitest::Test
  TLS = Raiha::TLS
  Handshake = TLS::Handshake
  Pair = NextTLSPair
  NOW = Pair::NOW

  TYPES = (Handshake::TYPES.keys - [254] + [0, 255, 25]).sort.freeze

  def state(machine) = machine.instance_variable_get(:@conductor).state

  def messages(outputs) = outputs.grep(TLS::Output::Message)

  def test_tables_cover_exactly_the_states
    [Handshake::ClientSide, Handshake::ServerSide].each do |side|
      assert_equal side::STATES.sort, side::EXPECTED.keys.sort, side.name
      assert_empty side::EXPECTED.fetch(:failed), side.name
    end
  end

  # Delivers the peer's messages one at a time until `machine` reaches
  # `target`, and returns it there.
  def advance(machine, peer_messages, target)
    peer_messages.each do |message|
      return machine if state(machine) == target
      machine.receive(message.bytes, epoch: message.epoch, now: NOW)
      flunk "failed with #{machine.alert} before #{target}" if machine.failed?
    end
    assert_equal target, state(machine)
    machine
  end

  # A client in `target`, against a server built by `server_options`.
  def client_at(target, server_options = {})
    client = Pair.client(identities: [Pair.client_identity])
    hello = messages(client.outputs).first
    server = Pair.server(hello.bytes, **server_options)
    flight = messages(server.outputs)
    if Handshake.parse(flight.first.bytes, registry: TLS::Extension::Registry::BUILTIN).hello_retry_request?
      advance(client, flight, :wait_sh2)
      return client if target == :wait_sh2
      server.receive(messages(client.outputs).first.bytes, epoch: :initial, now: NOW)
      flight = messages(server.outputs)
    end
    advance(client, flight, target)
  end

  def server_at(target, config: Pair.server_config)
    client = Pair.client(identities: [Pair.client_identity])
    server = Pair.server(messages(client.outputs).first.bytes, config:)
    return server if state(server) == target
    flight = messages(server.outputs)
    flight.each { |message| client.receive(message.bytes, epoch: message.epoch, now: NOW) }
    advance(server, messages(client.outputs), target)
  end

  CLIENT_STATES = {
    wait_sh: -> { Pair.client },
    wait_sh2: -> { client_at(:wait_sh2, config: Pair.server_config(groups: %i[secp256r1])) },
    wait_ee: -> { client_at(:wait_ee) },
    wait_cert_cr: -> { client_at(:wait_cert_cr, config: Pair.server_config(client_auth: :required)) },
    wait_cert: -> { client_at(:wait_cert, config: Pair.server_config(client_auth: :required)) },
    wait_cv: -> { client_at(:wait_cv) },
    wait_finished: -> { client_at(:wait_finished) },
    connected: -> { client_at(:connected) }
  }.freeze

  SERVER_STATES = {
    wait_ch2: -> { server_at(:wait_ch2, config: Pair.server_config(groups: %i[secp256r1])) },
    wait_cert: -> { server_at(:wait_cert, config: Pair.server_config(client_auth: :required)) },
    wait_cv: -> { server_at(:wait_cv, config: Pair.server_config(client_auth: :required)) },
    wait_finished: -> { server_at(:wait_finished) },
    connected: -> { server_at(:connected) }
  }.freeze

  # :wait_eoed needs 0-RTT, which is not built yet.
  def check(side, states)
    assert_equal side::STATES - [:failed, :wait_eoed], states.keys
    states.each do |name, build|
      epoch, expected = side::EXPECTED.fetch(name).first
      (TYPES - expected.to_a).each do |type|
        machine = instance_exec(&build)
        assert_equal name, state(machine)
        machine.outputs
        machine.receive([type, 0, 0, 0].pack("C4"), epoch:, now: NOW)
        assert_equal :unexpected_message, machine.alert, "#{side.name.split("::").last} #{name} given #{type}"
      end
    end
  end

  def test_client_rejects_every_unexpected_type
    check(Handshake::ClientSide, CLIENT_STATES)
  end

  def test_server_rejects_every_unexpected_type
    check(Handshake::ServerSide, SERVER_STATES)
  end

  # Bytes of an epoch other than the read epoch fail before the table is
  # read, in every state.
  def test_every_state_checks_the_epoch
    CLIENT_STATES.merge(SERVER_STATES.transform_keys { |name| :"server_#{name}" }).each do |name, build|
      machine = instance_exec(&build)
      other = (%i[initial handshake application] - [machine.read_epoch]).first
      machine.receive("\x14\x00\x00\x00".b, epoch: other, now: NOW)
      assert_equal :unexpected_message, machine.alert, name
      assert_equal :wrong_epoch, machine.each_event.grep(TLS::Event::Failed).first.reason, name
    end
  end

  # QUIC allows no KeyUpdate message (RFC 9001 "Key Update").
  def test_key_update_only_where_the_profile_allows_it
    tcp = Pair.client
    quic = Pair.client(config: Pair.client_config(profile: TLS::Profile::QUIC, alpn: ["h3"]),
      extensions: [TLS::Extension::Opaque.new(type: 0x39, data: "".b)])
    assert_includes tcp.instance_variable_get(:@conductor).side.expected_types(:connected, :application), 24
    refute_includes quic.instance_variable_get(:@conductor).side.expected_types(:connected, :application), 24
  end
end
