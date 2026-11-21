# A connection whose send buffer is acknowledged a byte at a time, one
# every `every` seconds, slower than three of its PTOs (81 ms): what
# Session#close_when_acknowledged waits on. It records what it closes with
# and how much was left.
class DrainingConnection
  Stats = Struct.new(:rtt, :rtt_var, :send_buffer_bytes)

  attr_reader :closed_with

  def initialize(bytes, every)
    @start = clock
    @bytes = bytes
    @every = every
    @closed_with = nil
  end

  def stats = Stats.new(0.001, 0.0, [@bytes - ((clock - @start) / @every).floor, 0].max)

  def each_event = nil

  def close_reason = nil

  def close(error_code:, reason:, application:, now:)
    @closed_with = [error_code, stats.send_buffer_bytes]
  end

  private def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)
end
