# frozen_string_literal: true

module Raiha::Quic
  class Timer
    attr_reader :deadline

    def initialize
      @deadline = nil
    end

    def set(duration)
      @deadline = Time.now + duration
    end

    def set_at(time)
      @deadline = time
    end

    def reset
      @deadline = nil
    end
    alias stop reset

    def expired?
      return false if @deadline.nil?

      Time.now >= @deadline
    end

    def active?
      !@deadline.nil?
    end

    def remaining
      return nil unless active?

      remaining_time = @deadline - Time.now
      remaining_time > 0 ? remaining_time : 0
    end
  end
end
