require "raiha/next/test_helper"
require "raiha/next/support/quic_frames"

# Bytes from the peer must never raise anything but Wire::Malformed from
# `Frame.parse`, and the Malformed must carry the error to close the
# connection with. Frames that parse must read back the same once written.
#
# Inputs are random byte strings, half of them after a known frame type so
# they reach the frame readers, and random frames with one byte changed, in
# a random packet type with a random ACK Delay exponent.
# RAIHA_FUZZ_ITERATIONS (default 10000) and RAIHA_FUZZ_SEED change the
# number of inputs and the seed.
class RaihaNextQUICWireFrameFuzzTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  Frame = QUIC::Wire::Frame

  ITERATIONS = Integer(ENV.fetch("RAIHA_FUZZ_ITERATIONS", "10000"))
  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "9000"))
  PACKET_TYPES = %i[initial handshake zero_rtt one_rtt].freeze
  CODES = [QUIC::ErrorCode::FRAME_ENCODING_ERROR, QUIC::ErrorCode::PROTOCOL_VIOLATION].freeze

  def random_input(rng)
    body = rng.bytes(rng.rand(0..300))
    return body if rng.rand(2).zero?
    QUIC::Wire::Varint.encode(Frame::BY_TYPE.keys.sample(random: rng)) + body
  end

  def mutated_input(rng)
    frames = NextQUICFrames.random_frames(rng, rng.rand(1..4))
    encoded = Frame.encode(frames, ack_delay_exponent: NextQUICFrames::ACK_DELAY_EXPONENT)
    encoded.setbyte(rng.rand(encoded.bytesize), rng.rand(256))
    encoded
  end

  def test_parse_raises_only_malformed
    rng = Random.new(SEED)
    parsed = 0
    ITERATIONS.times do |i|
      input = i.even? ? random_input(rng) : mutated_input(rng)
      packet_type = PACKET_TYPES.sample(random: rng)
      exponent = rng.rand(0..20)
      begin
        frames = Frame.parse(input, packet_type:, ack_delay_exponent: exponent)
        again = Frame.encode(frames, ack_delay_exponent: exponent)
        assert_equal frames, Frame.parse(again, packet_type:, ack_delay_exponent: exponent), "seed=#{SEED} iteration=#{i}"
        parsed += 1
      rescue QUIC::Wire::Malformed => e
        assert_includes CODES, e.code, "seed=#{SEED} iteration=#{i}: #{e.message}"
      rescue => e
        flunk "seed=#{SEED} iteration=#{i}: #{e.class}: #{e.message}\ninput=#{input.unpack1("H*")}\n#{e.backtrace.first(5).join("\n")}"
      end
    end
    # Changing one byte often leaves valid frames, so a run that never
    # parses anything has stopped exercising the readers.
    assert_operator parsed, :>, 0
  end
end
