require "test_helper"
require "support/tls_pair"

# Bytes from the peer never raise from `Machine#receive` or
# `Acceptor#receive`: whatever arrives, the handshake goes on or fails with
# an alert. Every target is fed in the epoch it reads, at each point of a
# real handshake, with the Verifier::Default the API design asks fuzzing to
# use.
#
# Inputs are random bytes, random bodies behind a well-formed header, and
# the real flight with one byte changed, a piece cut out, or bytes put in.
# RAIHA_FUZZ_ITERATIONS (default 300 per target) and RAIHA_FUZZ_SEED change
# the number of inputs and the seed.
class RaihaTLSReceiveFuzzTest < Minitest::Test
  TLS = Raiha::TLS
  Pair = TLSPair
  NOW = Pair::NOW

  ITERATIONS = Integer(ENV.fetch("RAIHA_FUZZ_ITERATIONS", "300"))
  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "9846"))
  TYPES = (TLS::Handshake::TYPES.keys - [254]).freeze

  def header(type, length) = [type].pack("C") + [length].pack("N").byteslice(1, 3)

  def input(rng, flight)
    case rng.rand(5)
    when 0 then rng.bytes(rng.rand(0..400))
    when 1
      body = rng.bytes(rng.rand(0..400))
      header(TYPES.sample(random: rng), body.bytesize) + body
    else
      bytes = flight.sample(random: rng).dup
      case rng.rand(3)
      when 0 then bytes.setbyte(rng.rand(bytes.bytesize), rng.rand(256))
      when 1 then bytes = bytes.byteslice(0, rng.rand(bytes.bytesize)).to_s + bytes.byteslice(rng.rand(bytes.bytesize)..).to_s
      else bytes.insert(rng.rand(bytes.bytesize), rng.bytes(rng.rand(1..8)))
      end
      bytes
    end
  end

  # Targets: [name, a builder of the receiver, the epoch it reads, the real
  # messages it would get next].
  def targets
    client = -> { Pair.client(identities: [Pair.client_identity]) }
    hello = client.call.outputs.first.bytes
    sample_client = client.call
    sample_server = Pair.server(sample_client.outputs.first.bytes, config: Pair.server_config(client_auth: :required))
    server_flight = sample_server.outputs.grep(TLS::Output::Message).map(&:bytes)
    [
      ["acceptor", -> { TLS::Handshake::Acceptor.new }, :initial, [hello]],
      ["server waiting for its ClientHello", -> { TLS::Handshake::Machine.server(config: (c = Pair.server_config), keyring: Pair.server_keyring(config: c), now: NOW) }, :initial, [hello]],
      ["client waiting for the ServerHello", client, :initial, server_flight.first(1)],
      ["client waiting for the server's flight", lambda do
        machine = client.call
        server = Pair.server(machine.outputs.first.bytes, config: Pair.server_config(client_auth: :required))
        machine.receive(server.outputs.grep(TLS::Output::Message).first.bytes, epoch: :initial, now: NOW)
        machine
      end, :handshake, server_flight.drop(1)],
      ["server waiting for the client's flight", lambda do
        machine = client.call
        server = Pair.server(machine.outputs.first.bytes, config: Pair.server_config(client_auth: :required))
        server.outputs
        server
      end, :handshake, server_flight.drop(1)]
    ]
  end

  def test_receive_never_raises
    rng = Random.new(SEED)
    targets.each do |name, build, epoch, flight|
      ITERATIONS.times do |i|
        receiver = build.call
        bytes = input(rng, flight)
        begin
          receiver.receive(bytes, epoch:, now: NOW)
          receiver.receive(input(rng, flight), epoch:, now: NOW) if rng.rand(2).zero?
        rescue StandardError => e
          flunk "#{name}, input #{i} (seed #{SEED}): #{e.class}: #{e.message}\n#{bytes.unpack1("H*")}"
        end
      end
    end
  end
end
