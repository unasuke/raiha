require "test_helper"
require "support/tcp_pair"

# Bytes from the peer never raise from `TCP::Connection#receive` or
# `TCP::Acceptor#receive`: whatever arrives, the connection goes on or fails
# with an alert. Each target is fed at a point of a real handshake.
#
# Inputs are random bytes, random bodies behind a well-formed record
# header, and the real records with one byte changed, a piece cut out, or
# bytes put in. RAIHA_FUZZ_ITERATIONS (default 300 per target) and
# RAIHA_FUZZ_SEED change the number of inputs and the seed.
class RaihaNextTLSTCPReceiveFuzzTest < Minitest::Test
  TLS = Raiha::TLS
  Pair = NextTCPPair
  NOW = Pair::NOW

  ITERATIONS = Integer(ENV.fetch("RAIHA_FUZZ_ITERATIONS", "300"))
  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "9846"))

  def input(rng, real)
    case rng.rand(5)
    when 0 then rng.bytes(rng.rand(0..400))
    when 1
      body = rng.bytes(rng.rand(0..400))
      [rng.rand(19..25), 0x0303, body.bytesize].pack("Cnn") + body
    else
      bytes = real.dup
      case rng.rand(3)
      when 0 then bytes.setbyte(rng.rand(bytes.bytesize), rng.rand(256))
      when 1 then bytes = bytes.byteslice(0, rng.rand(bytes.bytesize)).to_s + bytes.byteslice(rng.rand(bytes.bytesize)..).to_s
      else bytes.insert(rng.rand(bytes.bytesize), rng.bytes(rng.rand(1..8)))
      end
      bytes
    end
  end

  # [name, a builder of the receiver, the real bytes it would get next].
  def targets
    sample_client = Pair.client
    hello = Pair.take(sample_client)
    sample_server = Pair.server
    sample_server.receive(hello, now: NOW)
    first_flight = Pair.take(sample_server)
    sample_client.receive(first_flight, now: NOW)
    second_flight = Pair.take(sample_client)
    after_hello = lambda do
      client = Pair.client
      server = Pair.server
      server.receive(Pair.take(client), now: NOW)
      [client, server]
    end
    connected = Pair.connect
    connected.server.write("application data")
    data = Pair.take(connected.server)
    [
      ["acceptor", -> { TLS::TCP::Acceptor.new }, hello],
      ["server waiting for its ClientHello", -> { Pair.server }, hello],
      ["client waiting for the server's flight", -> { Pair.client.tap { |client| Pair.take(client) } }, first_flight],
      ["server waiting for the client's flight", -> { after_hello.call.last.tap { |server| Pair.take(server) } }, second_flight],
      ["connected client", -> { Pair.connect.client }, data]
    ]
  end

  def test_receive_never_raises
    rng = Random.new(SEED)
    targets.each do |name, build, real|
      ITERATIONS.times do |i|
        receiver = build.call
        bytes = input(rng, real)
        begin
          receiver.receive(bytes, now: NOW)
          receiver.receive(input(rng, real), now: NOW) if rng.rand(2).zero?
        rescue StandardError => e
          flunk "#{name}, input #{i} (seed #{SEED}): #{e.class}: #{e.message}\n#{bytes.unpack1("H*")}"
        end
      end
    end
  end
end
