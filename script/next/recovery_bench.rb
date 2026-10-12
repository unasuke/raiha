#!/usr/bin/env ruby
# frozen_string_literal: true

# Allocations and time per packet of loss recovery, to see regressions by
# hand (loss recovery's design, "Performance"): 200,000 packets with one
# STREAM duty each, 64 in flight, an ACK every two packets and 1% lost,
# found by the packet threshold. The baseline runs the same without loss
# recovery: the duties, the peer and its ACK frames only. Allocations come
# out the same each run; time is for reference.
#
# Usage: bundle exec ruby script/next/recovery_bench.rb [--yjit]

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))

require "raiha/next/quic"

QUIC = Raiha::Next::QUIC
PACKETS = 200_000
IN_FLIGHT = 64
LOSS_RATE = 0.01
# The ranges an ACK frame carries, the latest.
ACK_RANGES = 4

def run(recovery)
  rng = Random.new(1)
  now = 0.0
  # Sent and yet to reach the peer, in order; nil for one lost.
  flying = []
  ranges = []
  sent = 0
  while sent < PACKETS || !flying.empty?
    while sent < PACKETS && flying.size < IN_FLIGHT
      duties = [QUIC::Recovery::Duty::Stream.new(stream_id: 0, offset: sent * 1200, length: 1200, fin: false)]
      number = recovery ? recovery.next_packet_number(:one_rtt) : sent
      if recovery
        recovery.on_packet_sent(packet_type: :one_rtt, packet_number: number, sent_bytes: 1252, ack_eliciting: true, in_flight: true,
          duties:, now:)
      end
      flying << (rng.rand < LOSS_RATE ? nil : number)
      sent += 1
    end
    now += 0.0005
    flying.shift(2).each do |number|
      next unless number
      last = ranges.last
      if last && last.end == number - 1
        ranges[-1] = last.begin..number
      else
        ranges << (number..number)
        ranges.shift if ranges.size > ACK_RANGES
      end
    end
    next if ranges.empty?
    ack = QUIC::Wire::Frame::Ack.new(ranges: ranges.reverse, delay: 0.0)
    recovery&.on_ack_received(packet_type: :one_rtt, ack:, now: now + 0.02)
  end
end

def measure(name)
  recovery = yield
  GC.start
  allocated = GC.stat(:total_allocated_objects)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  run(recovery)
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  per_packet = (GC.stat(:total_allocated_objects) - allocated).fdiv(PACKETS)
  puts format("%-10s %6.2f allocations/packet %6.2f µs/packet", name, per_packet, elapsed * 1_000_000 / PACKETS)
  per_packet
end

puts "#{RUBY_DESCRIPTION}, #{PACKETS} packets"
baseline = measure("baseline") { nil }
recovery = measure("recovery") do
  config = QUIC::Config.new
  QUIC::Recovery.new(role: :server, config:, path: QUIC::Path.new(config:), random: Random.new(1), now: 0.0).tap do |recovery|
    recovery.handshake_confirmed!(now: 0.0)
  end
end
puts format("%-10s %6.2f allocations/packet", "difference", recovery - baseline)
