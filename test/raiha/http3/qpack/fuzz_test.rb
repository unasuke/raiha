require "test_helper"
require "raiha/http3/qpack"

# What the peer sends never raises out of the decoder or the encoder: it
# comes back as a result or a Failure. The inputs are random bytes, and
# sections and instructions that decode with a byte changed, cut short or
# lengthened. RAIHA_FUZZ_ITERATIONS (default 300) and RAIHA_FUZZ_SEED
# change the number of inputs to each target and the seed.
class RaihaQPACKFuzzTest < Minitest::Test
  QPACK = Raiha::HTTP3::QPACK

  ITERATIONS = Integer(ENV.fetch("RAIHA_FUZZ_ITERATIONS", "300"))
  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "9204"))
  RESULTS = [QPACK::Decoded, QPACK::Blocked, QPACK::Oversized, QPACK::Failure].freeze

  # Encoder instructions that decode, with a table of 4096 octets.
  INSTRUCTIONS = [
    QPACK::Writer.new.integer(4096, 5, 0x20).to_s,
    QPACK::Writer.new.string("custom-key".b, 6, 0x40).string("custom-value".b, 8).to_s,
    QPACK::Writer.new.integer(0, 6, 0xc0).string("www.example.com".b, 8).to_s,
    QPACK::Writer.new.integer(0, 6, 0x80).string("other".b, 8).to_s,
    QPACK::Writer.new.integer(1, 5).to_s
  ].join.freeze

  def test_decoding_random_bytes
    run_fuzz("decode") do |rng|
      decoder = decoder_with_entries
      result = decoder.decode(rng.rand(0..100) * 4, rng.bytes(rng.rand(0..80)), limit: rng.rand(0..2_000))
      assert_includes RESULTS, result.class
    end
  end

  def test_decoding_sections_with_a_byte_changed
    run_fuzz("decode a changed section") do |rng|
      decoder = decoder_with_entries
      section = mutate(rng, valid_section(rng))
      assert_includes RESULTS, decoder.decode(0, section).class
      assert_kind_of Array, decoder.receive_encoder_stream(INSTRUCTIONS).then { _1.is_a?(QPACK::Failure) ? [] : _1 }
      assert_kind_of String, decoder.take_instructions
    end
  end

  def test_following_random_encoder_streams
    run_fuzz("receive_encoder_stream") do |rng|
      decoder = QPACK::Decoder.new(max_table_capacity: rng.rand(0..4096), max_blocked_streams: rng.rand(0..4))
      decoder.decode(4, "\x02\x00\x80".b)
      3.times do
        result = decoder.receive_encoder_stream(rng.rand(2).zero? ? rng.bytes(rng.rand(0..40)) : mutate(rng, INSTRUCTIONS))
        assert(result.is_a?(QPACK::Failure) || result.all? { RESULTS.include?(_1.class) })
      end
    end
  end

  def test_following_random_decoder_streams
    run_fuzz("receive_decoder_stream") do |rng|
      encoder = QPACK::Encoder.new
      result = encoder.receive_decoder_stream(rng.bytes(rng.rand(0..20)))
      assert(result.nil? || result.is_a?(QPACK::Failure))
    end
  end

  private def decoder_with_entries
    QPACK::Decoder.new(max_table_capacity: 4096, max_blocked_streams: 2).tap { _1.receive_encoder_stream(INSTRUCTIONS) }
  end

  # A section that decodes against the entries of INSTRUCTIONS: the
  # encoder's, or one that refers to the dynamic table.
  private def valid_section(rng)
    if rng.rand(2).zero?
      fields = Array.new(rng.rand(1..4)) { QPACK::Field.new(name: rng.bytes(rng.rand(1..8)), value: rng.bytes(rng.rand(0..20))) }
      QPACK::Encoder.new.encode(0, fields)
    else
      QPACK::Writer.new.integer(5, 8).integer(0, 7).integer(0, 6, 0x80).integer(1, 4, 0x40).string("v".b, 8).to_s
    end
  end

  private def mutate(rng, bytes)
    bytes = bytes.dup
    case rng.rand(3)
    when 0
      bytes.setbyte(rng.rand(bytes.bytesize), rng.rand(256)) unless bytes.empty?
      bytes
    when 1 then bytes.byteslice(0, rng.rand(0..bytes.bytesize)).to_s
    else bytes + rng.bytes(rng.rand(1..10))
    end
  end

  # Runs the block ITERATIONS times; an exception from it fails with the
  # iteration to rerun.
  private def run_fuzz(label)
    rng = Random.new(SEED)
    ITERATIONS.times do |iteration|
      yield rng
    rescue Minitest::Assertion
      raise
    rescue => error
      flunk "#{label} seed=#{SEED} iteration=#{iteration}: #{error.class}: #{error.message}\n#{error.backtrace&.first(8)&.join("\n")}"
    end
  end
end
