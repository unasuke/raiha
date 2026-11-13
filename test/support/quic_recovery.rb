require "raiha/quic"

# Helpers for the tests of loss recovery.
module NextQUICRecovery
  QUIC = Raiha::QUIC

  # A tracer that keeps every event as [name, keywords], and asks for the
  # frames unless `frames` is false.
  class RecordingTracer
    include Raiha::QUIC::Tracer

    attr_reader :events

    def initialize(frames: true)
      @events = []
      @frames = frames
    end

    (Raiha::QUIC::Tracer.instance_methods(false) - [:trace_frames?]).each do |name|
      define_method(name) { |**keywords| @events << [name, keywords] }
    end

    def trace_frames? = @frames

    def of(name) = @events.filter_map { |event, keywords| keywords if event == name }
  end

  module_function

  def recovery(role: :client, config: QUIC::Config.new, path: QUIC::Path.new(config:), tracer: nil, seed: 1, now: 0.0)
    QUIC::Recovery.new(role:, config:, path:, random: Random.new(seed), tracer:, now:)
  end

  # An ACK frame of `ranges`, the largest first.
  def ack(*ranges, delay: 0.0, ecn: nil) = QUIC::Wire::Frame::Ack.new(ranges:, delay:, ecn:)

  # Sends a packet of `packet_type` at `now` and gives its number.
  def send_packet(recovery, packet_type, now:, sent_bytes: 1200, ack_eliciting: true, in_flight: true, duties: [])
    packet_number = recovery.next_packet_number(packet_type)
    recovery.on_packet_sent(packet_type:, packet_number:, sent_bytes:, ack_eliciting:, in_flight:, duties:, now:)
    packet_number
  end
end
