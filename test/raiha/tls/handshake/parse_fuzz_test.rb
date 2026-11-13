require "test_helper"
require "raiha/tls/test"

# Bytes from the peer must never raise anything but Codec::Malformed from
# `Handshake.parse`, and a message that parses must not make `#validate`
# raise either.
#
# Inputs are random byte strings, half of them behind a well-formed header of
# a known type so they reach the message parsers, and RFC 8448 messages with
# one byte changed. RAIHA_FUZZ_ITERATIONS (default 10000) and
# RAIHA_FUZZ_SEED change the number of inputs and the seed.
class RaihaTLSHandshakeParseFuzzTest < Minitest::Test
  TLS = Raiha::TLS
  RFC8448 = TLS::Test::RFC8448
  REGISTRY = TLS::Extension::Registry::BUILTIN

  ITERATIONS = Integer(ENV.fetch("RAIHA_FUZZ_ITERATIONS", "10000"))
  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "8448"))

  SAMPLES = [
    RFC8448::Simple1RTT::CLIENT_HELLO, RFC8448::Simple1RTT::SERVER_HELLO,
    RFC8448::Simple1RTT::ENCRYPTED_EXTENSIONS, RFC8448::Simple1RTT::CERTIFICATE,
    RFC8448::Simple1RTT::CERTIFICATE_VERIFY, RFC8448::Simple1RTT::SERVER_FINISHED,
    RFC8448::Simple1RTT::CLIENT_FINISHED, RFC8448::Simple1RTT::NEW_SESSION_TICKET,
    RFC8448::Resumed0RTT::CLIENT_HELLO, RFC8448::Resumed0RTT::SERVER_HELLO,
    RFC8448::HelloRetryRequest::CLIENT_HELLO_1, RFC8448::HelloRetryRequest::HELLO_RETRY_REQUEST,
    RFC8448::HelloRetryRequest::CLIENT_HELLO_2, RFC8448::HelloRetryRequest::SERVER_HELLO
  ].freeze

  KNOWN_TYPES = TLS::Handshake::TYPES.keys.freeze

  def random_input(rng)
    body = rng.bytes(rng.rand(0..600))
    return body if rng.rand(2).zero?
    [KNOWN_TYPES.sample(random: rng)].pack("C") + [body.bytesize].pack("N").byteslice(1, 3) + body
  end

  def mutated_input(rng)
    sample = SAMPLES.sample(random: rng).dup
    sample.setbyte(rng.rand(sample.bytesize), rng.rand(256))
    sample
  end

  def test_parse_raises_only_malformed
    rng = Random.new(SEED)
    parsed = 0
    ITERATIONS.times do |i|
      input = i.even? ? random_input(rng) : mutated_input(rng)
      begin
        message = TLS::Handshake.parse(input, registry: REGISTRY)
        message.validate
        parsed += 1
      rescue TLS::Codec::Malformed
        nil
      rescue => e
        flunk "seed=#{SEED} iteration=#{i}: #{e.class}: #{e.message}\ninput=#{input.unpack1("H*")}\n#{e.backtrace.first(5).join("\n")}"
      end
    end
    # Mutating one byte often leaves a valid message, so a run that never
    # parses anything has stopped exercising the parsers.
    assert_operator parsed, :>, 0
  end
end
