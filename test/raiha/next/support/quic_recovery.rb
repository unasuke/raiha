require "raiha/next/quic"

# Helpers for the tests of loss recovery.
module NextQUICRecovery
  QUIC = Raiha::Next::QUIC

  # A tracer that keeps every event as [name, keywords].
  class RecordingTracer
    include Raiha::Next::QUIC::Tracer

    attr_reader :events

    def initialize = @events = []

    Raiha::Next::QUIC::Tracer.instance_methods(false).each do |name|
      define_method(name) { |**keywords| @events << [name, keywords] }
    end

    def of(name) = @events.filter_map { |event, keywords| keywords if event == name }
  end

  module_function

  def recovery(config: QUIC::Config.new, path: QUIC::Path.new(config:), tracer: nil, seed: 1, now: 0.0)
    QUIC::Recovery.new(config:, path:, random: Random.new(seed), tracer:, now:)
  end

  # Sends a packet of `packet_type` at `now` and gives its number.
  def send_packet(recovery, packet_type, now:, sent_bytes: 1200, ack_eliciting: true, in_flight: true, duties: [])
    packet_number = recovery.next_packet_number(packet_type)
    recovery.on_packet_sent(packet_type:, packet_number:, sent_bytes:, ack_eliciting:, in_flight:, duties:, now:)
    packet_number
  end
end
