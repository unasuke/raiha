require "raiha/quic"

# Random QUIC frames of every kind, with values spread over every length of
# varint, for the round-trip and fuzz tests of Wire::Frame.
module NextQUICFrames
  Frame = Raiha::Next::QUIC::Wire::Frame

  # The exponent the frames' ACK Delay is chosen for, so that it survives a
  # round trip exactly.
  ACK_DELAY_EXPONENT = 3

  module_function

  # A value that takes 1, 2, 4 or 8 bytes as a varint, up to `max`.
  def varint(rng, max = Raiha::Next::QUIC::Wire::Varint::MAX)
    [rng.rand(64), rng.rand(16_384), rng.rand(1 << 30), rng.rand(1 << 62)].sample(random: rng).clamp(0, max)
  end

  def bytes(rng, range) = rng.bytes(rng.rand(range))

  def ack(rng)
    largest = varint(rng)
    ranges = []
    top = largest
    rng.rand(1..8).times do
      bottom = top - rng.rand(0..[top, 100].min)
      ranges << (bottom..top)
      top = bottom - 2 - rng.rand(0..100)
      break if top.negative?
    end
    delay = rng.rand(1 << 20) * (1 << ACK_DELAY_EXPONENT) / 1_000_000.0
    ecn = rng.rand(2).zero? ? nil : Frame::Ack::ECNCounts.new(ect0: varint(rng), ect1: varint(rng), ce: varint(rng))
    Frame::Ack.new(ranges:, delay:, ecn:)
  end

  def random_frame(rng)
    case rng.rand(22)
    when 0 then Frame::Padding.new(length: rng.rand(1..40))
    when 1 then Frame::Ping.new
    when 2 then ack(rng)
    when 3 then Frame::ResetStream.new(stream_id: varint(rng), error_code: varint(rng), final_size: varint(rng))
    when 4 then Frame::StopSending.new(stream_id: varint(rng), error_code: varint(rng))
    when 5 then Frame::Crypto.new(offset: varint(rng, 1 << 40), data: bytes(rng, 0..200))
    when 6 then Frame::NewToken.new(token: bytes(rng, 1..100))
    when 7 then Frame::Stream.new(stream_id: varint(rng), offset: varint(rng, 1 << 40), data: bytes(rng, 0..200), fin: rng.rand(2).zero?)
    when 8 then Frame::MaxData.new(maximum: varint(rng))
    when 9 then Frame::MaxStreamData.new(stream_id: varint(rng), maximum: varint(rng))
    when 10 then Frame::MaxStreams.new(bidirectional: rng.rand(2).zero?, maximum: varint(rng, Frame::MAX_STREAM_COUNT))
    when 11 then Frame::DataBlocked.new(maximum: varint(rng))
    when 12 then Frame::StreamDataBlocked.new(stream_id: varint(rng), maximum: varint(rng))
    when 13 then Frame::StreamsBlocked.new(bidirectional: rng.rand(2).zero?, maximum: varint(rng, Frame::MAX_STREAM_COUNT))
    when 14
      sequence_number = varint(rng)
      Frame::NewConnectionID.new(sequence_number:, retire_prior_to: rng.rand(0..sequence_number),
        connection_id: rng.bytes(rng.rand(1..20)), stateless_reset_token: rng.bytes(16))
    when 15 then Frame::RetireConnectionID.new(sequence_number: varint(rng))
    when 16 then Frame::PathChallenge.new(data: rng.bytes(8))
    when 17 then Frame::PathResponse.new(data: rng.bytes(8))
    when 18 then Frame::ConnectionClose.new(code: varint(rng), frame_type: varint(rng), reason: bytes(rng, 0..50), application: false)
    when 19 then Frame::ConnectionClose.new(code: varint(rng), frame_type: nil, reason: bytes(rng, 0..50), application: true)
    when 20 then Frame::HandshakeDone.new
    else Frame::Datagram.new(data: bytes(rng, 0..200))
    end
  end

  # Up to `count` frames that a 1-RTT packet may carry one after another and
  # that read back as written: no two PADDING runs in a row, which would
  # read as one.
  def random_frames(rng, count)
    frames = []
    count.times do
      frame = random_frame(rng)
      next if frame.is_a?(Frame::Padding) && frames.last.is_a?(Frame::Padding)
      frames << frame
    end
    frames
  end
end
