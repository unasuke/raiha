require "test_helper"
require "raiha/quic"

# The peer's quic_transport_parameters must never raise anything but
# Wire::Malformed with TRANSPORT_PARAMETER_ERROR from
# `TransportParameters.decode`, and what decodes must decode the same once
# encoded again.
#
# Inputs are random byte strings, half of them as a run of parameters with
# known IDs, and the encoding of a client's and a server's parameters with
# one byte changed, from a random sender. RAIHA_FUZZ_ITERATIONS (default
# 10000) and RAIHA_FUZZ_SEED change the number of inputs and the seed.
class RaihaNextQUICTransportParametersFuzzTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  TP = QUIC::TransportParameters

  ITERATIONS = Integer(ENV.fetch("RAIHA_FUZZ_ITERATIONS", "10000"))
  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "9002"))

  SAMPLES = [
    QUIC::Config.new.transport_parameters(initial_source_connection_id: "c".b * 8).encode,
    QUIC::Config.new(max_datagram_frame_size: 65_535, disable_active_migration: true).transport_parameters(
      initial_source_connection_id: "s".b * 8, original_destination_connection_id: "o".b * 8, retry_source_connection_id: "r".b * 8,
      stateless_reset_token: "t".b * 16,
      preferred_address: TP::PreferredAddress.new(ipv4: ["192.0.2.1", 443], ipv6: ["2001:db8::1", 443],
        connection_id: "p".b * 8, stateless_reset_token: "q".b * 16)
    ).encode
  ].freeze

  def random_input(rng)
    return rng.bytes(rng.rand(0..200)) if rng.rand(2).zero?
    Array.new(rng.rand(1..8)) do
      value = rng.bytes(rng.rand(0..24))
      QUIC::Wire::Varint.encode(TP::IDS.values.sample(random: rng)) + QUIC::Wire::Varint.encode(value.bytesize) + value
    end.join
  end

  def mutated_input(rng)
    sample = SAMPLES.sample(random: rng).dup
    sample.setbyte(rng.rand(sample.bytesize), rng.rand(256))
    sample
  end

  def test_decode_raises_only_transport_parameter_error
    rng = Random.new(SEED)
    decoded = 0
    ITERATIONS.times do |i|
      input = i.even? ? random_input(rng) : mutated_input(rng)
      sender = %i[client server].sample(random: rng)
      begin
        parameters = TP.decode(input, sender:)
        assert_equal parameters, TP.decode(parameters.encode, sender:), "seed=#{SEED} iteration=#{i}"
        decoded += 1
      rescue QUIC::Wire::Malformed => e
        assert_equal QUIC::ErrorCode::TRANSPORT_PARAMETER_ERROR, e.code, "seed=#{SEED} iteration=#{i}: #{e.message}"
      rescue => e
        flunk "seed=#{SEED} iteration=#{i}: #{e.class}: #{e.message}\ninput=#{input.unpack1("H*")}\n#{e.backtrace.first(5).join("\n")}"
      end
    end
    # Changing one byte often leaves valid parameters, so a run that never
    # decodes anything has stopped exercising the checks.
    assert_operator decoded, :>, 0
  end
end
