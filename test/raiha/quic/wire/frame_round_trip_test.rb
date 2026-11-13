require "test_helper"
require "support/quic_frames"

# Random frames of every kind, with values over every length of varint,
# read back as they were written. RAIHA_FUZZ_ITERATIONS (default 10000) and
# RAIHA_FUZZ_SEED change the number of payloads and the seed.
class RaihaQUICWireFrameRoundTripTest < Minitest::Test
  Frame = Raiha::QUIC::Wire::Frame

  ITERATIONS = Integer(ENV.fetch("RAIHA_FUZZ_ITERATIONS", "10000"))
  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "9000"))

  def test_frames_read_back_as_written
    rng = Random.new(SEED)
    exponent = QUICFrames::ACK_DELAY_EXPONENT
    kinds = Set.new
    ITERATIONS.times do |i|
      frames = QUICFrames.random_frames(rng, rng.rand(1..6))
      encoded = Frame.encode(frames, ack_delay_exponent: exponent)
      assert_equal frames, Frame.parse(encoded, packet_type: :one_rtt, ack_delay_exponent: exponent), "seed=#{SEED} iteration=#{i}"
      frames.each { |frame| kinds << frame.class }
    end
    assert_equal Frame::KINDS.to_set, kinds
  end
end
