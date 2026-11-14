# frozen_string_literal: true

require "fileutils"

module Raiha::Runtime
  # The qlog of the connections of a client or a server of the runtime, a
  # file of its own for each in one directory. A trace writes to memory, as
  # a call into the core never waits, and what it wrote goes to its file
  # when the driver's owner flushes after its turn. The traces of a worker,
  # a Ractor, all draw on one QUIC::Qlog::Budget, 1 GiB, however many
  # connections it has had: what it has spent does not come back.
  #
  # The files of the directory are kept to `max_bytes` (1 GiB) and
  # `max_files` (4,096) together, those of earlier runs included: before a
  # new trace begins, the oldest files not being written are taken away.
  # The directory is looked at once; after that, what the Qlog itself has
  # closed is all it counts. A trace holds its file under an exclusive
  # flock while it writes, and a file whose lock cannot be had, which
  # another Qlog or process sharing the directory is writing, is neither
  # taken away nor counted.
  #
  # A server's file is named by a connection ID the client chose, so
  # whoever can write to the directory could put a FIFO or a symbolic link
  # there under that name first. Files are opened without following links
  # and without waiting, and used only when they are regular files; a trace
  # whose file cannot be had so is dropped.
  class Qlog
    BUDGET = 1024 * 1024 * 1024
    MAX_FILES = 4096

    # What one trace has written and not yet put in its file: the IO its
    # tracer writes to.
    class Pending
      attr_reader :path

      # The bytes written so far.
      attr_reader :size

      def initialize(path)
        @path = path
        @data = "".b
        @file = nil #: File?
        @over = false
        @size = 0
        @dropped = false
      end

      def write(*strings)
        strings.sum do |string|
          @data << string
          @size += string.bytesize
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
          file = (@file ||= open_locked)
          file&.write(data)
        end
        return false unless @over
        @file&.close
        true
      end

      # The file, a regular one held under an exclusive lock while the trace
      # writes it; nil, and the trace dropped, when it cannot be had so.
      private def open_locked
        return nil if @dropped
        flags = File::WRONLY | File::APPEND | File::CREAT | File::NOFOLLOW | File::NONBLOCK
        # A trace has what the peers said, which is no one else's to read.
        file = File.open(@path, flags, 0o600)
        return file if file.stat.file? && file.flock(File::LOCK_EX | File::LOCK_NB)
        file.close
        @dropped = true
        nil
      rescue SystemCallError
        @dropped = true
        nil
      end
    end

    # The budget of the traces of the current Ractor.
    def self.budget
      Ractor.current[:raiha_next_runtime_qlog_budget] ||= Raiha::QUIC::Qlog::Budget.new(max_bytes: BUDGET) #: Raiha::QUIC::Qlog::Budget
    end

    attr_reader :budget

    def initialize(dir, budget: Qlog.budget, max_bytes: BUDGET, max_files: MAX_FILES)
      FileUtils.mkdir_p(dir)
      @dir = dir
      @budget = budget
      @max_bytes = max_bytes
      @max_files = max_files
      @pending = [] #: Array[Pending]
      # The files no trace writes to, oldest first, with their sizes.
      @closed = files_by_age
    end

    # A tracer of a connection seen from `vantage_point` (:client or
    # :server), in the file "<name>_<vantage point>.sqlog", and its Pending,
    # to be told when the connection is over. A connection whose ALPN may
    # be HTTP/3 names the schema of HTTP/3's events too, which an
    # HTTP3::Qlog::Tracer over this one records.
    def trace(vantage_point, name, tls_config:)
      rotate
      pending = Pending.new(File.join(@dir, "#{name}_#{vantage_point}.sqlog"))
      @pending << pending
      event_schemas = tls_config.alpn.include?("h3") ? [Raiha::HTTP3::Qlog::EVENT_SCHEMA] : [] #: Array[String]
      [Raiha::QUIC::Qlog::Tracer.new(pending, vantage_point:, budget: @budget, event_schemas:), pending]
    end

    # Puts what the traces have written in their files, and lets go those
    # whose connections are over.
    def flush
      done = @pending.select(&:flush)
      @pending -= done
      done.each { |pending| @closed << [pending.path, pending.size] }
      nil
    end

    # The qlog files already in the directory, oldest first, with their
    # sizes.
    private def files_by_age
      files = Dir.glob(File.join(@dir, "*.sqlog")).filter_map do |path|
        stat = File.stat(path)
        next nil unless stat.file?
        [path, stat] #: [String, File::Stat]
      rescue SystemCallError
        nil
      end
      files.sort_by { |_, stat| stat.mtime }.map do |path, stat|
        [path, stat.size] #: [String, Integer]
      end
    end

    # Takes the oldest files no trace writes to away until one more file
    # fits within `max_files`, and what is there within `max_bytes`.
    private def rotate
      bytes = @closed.sum { |_, size| size } + @pending.sum(&:size)
      while (oldest = @closed.first) && (@closed.size + @pending.size + 1 > @max_files || bytes > @max_bytes)
        @closed.shift
        bytes -= oldest[1]
        delete(oldest[0])
      end
    end

    # Takes a file away when it is a regular file no other writer holds the
    # lock of; one that has gone already is gone.
    private def delete(path)
      File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
        File.delete(path) if file.stat.file? && file.flock(File::LOCK_EX | File::LOCK_NB)
      end
    rescue SystemCallError
      nil
    end
  end
end
