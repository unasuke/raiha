# frozen_string_literal: true

require "fileutils"

module Raiha::Next::Runtime
  # The qlog of the connections of a client or a server of the runtime, a
  # file of its own for each in one directory. A trace writes to memory, as
  # a call into the core never waits, and what it wrote goes to its file
  # when the driver's owner flushes after its turn. The traces of a worker,
  # a Ractor, all draw on one QUIC::Qlog::Budget, 1 GiB, however many
  # connections it has had: what it has spent does not come back.
  class Qlog
    BUDGET = 1024 * 1024 * 1024

    # What one trace has written and not yet put in its file: the IO its
    # tracer writes to.
    class Pending
      attr_reader :path

      def initialize(path)
        @path = path
        @data = "".b
        @file = nil #: File?
        @over = false
      end

      def write(*strings)
        strings.sum do |string|
          @data << string
          string.bytesize
        end
      end

      # The connection is over: the file closes once flushed.
      def over!
        @over = true
      end

      # Puts what is pending in the file, opened the first time; whether the
      # file is done with. The write may yield, so what the tracer writes
      # meanwhile is kept for the next flush.
      def flush
        unless @data.empty?
          data = @data
          @data = "".b
          (@file ||= File.open(@path, "ab")).write(data)
        end
        return false unless @over
        @file&.close
        true
      end
    end

    # The budget of the traces of the current Ractor.
    def self.budget
      Ractor.current[:raiha_next_runtime_qlog_budget] ||= Raiha::Next::QUIC::Qlog::Budget.new(max_bytes: BUDGET) #: Raiha::Next::QUIC::Qlog::Budget
    end

    attr_reader :budget

    def initialize(dir, budget: Qlog.budget)
      FileUtils.mkdir_p(dir)
      @dir = dir
      @budget = budget
      @pending = [] #: Array[Pending]
    end

    # A tracer of a connection seen from `vantage_point` (:client or
    # :server), in the file "<name>_<vantage point>.sqlog", and its Pending,
    # to be told when the connection is over.
    def trace(vantage_point, name)
      pending = Pending.new(File.join(@dir, "#{name}_#{vantage_point}.sqlog"))
      @pending << pending
      [Raiha::Next::QUIC::Qlog::Tracer.new(pending, vantage_point:, budget: @budget), pending]
    end

    # Puts what the traces have written in their files, and lets go those
    # whose connections are over.
    def flush
      done = @pending.select(&:flush)
      @pending -= done
      nil
    end
  end
end
