# frozen_string_literal: true

require "securerandom"

module Raiha::Next::Runtime
  # The workers of a server, each in a Ractor of its own: `run` binds a
  # socket for each worker to `host` and `port` with SO_REUSEPORT, and one
  # for each preferred address of `config` the first does not take, moves
  # them to the workers' Ractors, and runs the block in each with its
  # Worker and `args`, which have to be shareable or copied. The block
  # makes a server with `worker:` and `config: worker.config` and runs it,
  # under a Fiber scheduler of its own.
  #
  # `config` is the QUIC Config every worker shares; the Retry token and
  # stateless reset keys it leaves out are drawn once here, so that each
  # worker takes the tokens and reads the connection IDs another issued.
  # Its connection IDs are WorkerConnectionIDs::MIN_LENGTH bytes at least,
  # to carry the worker's ID. The workers share one record of 0-RTT
  # (TLS::AntiReplay::Shared), in a Ractor of its own.
  #
  # Once one worker's block is over, the others are told to stop; `run`
  # returns when all are over, raising what the first that raised raised.
  # The record stopping before them is a failure too.
  #
  # `stop` asks every worker to stop, from a signal handler as well,
  # `reconfigure` has every worker take other TLS settings, building its
  # Keyring of `identities`, and `stats` gives what each worker counted of
  # the datagrams handed on, nil for one that does not answer in time.
  #
  # SO_REUSEPORT spreads datagrams over sockets on Linux alone, where more
  # than one worker can be run.
  class Workers
    MAX = Raiha::Next::QUIC::WorkerConnectionIDs::MAX_WORKERS
    # How long `stats` waits for a worker to answer.
    STATS_TIMEOUT = 1.0

    attr_reader :count

    def initialize(count:, config:, host: "::", port: 443, args: [], &block)
      raise ArgumentError, "a block to run in each worker is needed" unless block
      raise ArgumentError, "count #{count} is not 1 to #{MAX}" unless count.is_a?(Integer) && (1..MAX).cover?(count)
      raise Error::Usage, "SO_REUSEPORT spreads datagrams over workers on Linux alone" if count > 1 && !RUBY_PLATFORM.include?("linux")
      if config.connection_id_length < Raiha::Next::QUIC::WorkerConnectionIDs::MIN_LENGTH
        raise ArgumentError, "a worker's connection IDs are #{Raiha::Next::QUIC::WorkerConnectionIDs::MIN_LENGTH} bytes at least"
      end
      @count = count
      @config = config.with(retry_token_key: config.retry_token_key || SecureRandom.bytes(Raiha::Next::QUIC::Config::MIN_KEY_LENGTH),
        stateless_reset_key: config.stateless_reset_key || SecureRandom.bytes(Raiha::Next::QUIC::Config::MIN_KEY_LENGTH))
      @host = host
      @port = port
      @args = args
      @body = Ractor.shareable_proc(&block) # steep:ignore
      @local_address = nil #: UDP::address?
      @controls = [] #: Array[Ractor::Port[Worker::control]]
      # What `stop` asked, and the pipe it wakes `run` through.
      @stop = nil #: (Float | Integer)?
      @wake = nil #: IO?
    end

    # [address, port] the workers' sockets are bound to, once `run` bound
    # them.
    def local_address = @local_address

    # Runs the workers until all are over; raises what the first that
    # raised raised.
    def run
      reader, @wake = IO.pipe
      sockets = bind
      shared, record = Raiha::Next::TLS::AntiReplay::Shared.start(now: Time.now)
      out = Ractor::Port.new
      ractors = Array.new(@count) { |id| start(id, out, shared) }
      started = Array.new(@count) { out.receive }.sort_by(&:first)
      peers = Ractor.make_shareable(started.map { |_, inbox, _| inbox })
      @controls = started.map { |_, _, control| control }
      ractors.each_with_index { |ractor, id| ractor.send([sockets[id], peers], move: true) }
      sockets = nil
      relay = Thread.new { relay_stops(reader) }
      (timeout = @stop) and stop_workers(timeout)
      wait(ractors, record)
    ensure
      relay&.kill
      reader&.close
      @wake&.close
      sockets&.flatten&.each(&:close)
      shared&.stop
      begin
        record&.join
      rescue Ractor::RemoteError
        nil
      end
    end

    # Asks every worker to stop, giving its sessions `timeout` seconds; the
    # first call is the one that counts. It writes to a pipe without
    # waiting, so a signal handler may call it, and `run` tells the workers.
    def stop(timeout: Server::STOP_TIMEOUT)
      @stop ||= timeout
      @wake&.write_nonblock(".", exception: false)
      nil
    rescue IOError, SystemCallError
      # `run` is returning and has closed the pipe.
      nil
    end

    # Has every worker take the connections to come with `tls_config` and
    # a Keyring of `identities` (TLS::Keyring::Identity); those taken keep
    # theirs.
    def reconfigure(tls_config:, identities:)
      raise Error::Usage, "the workers are not running" if @controls.empty?
      message = Ractor.make_shareable([:reconfigure, tls_config, identities], copy: true) #: Worker::control
      @controls.each do |control|
        control.send(message)
      rescue Ractor::ClosedError
        nil
      end
      nil
    end

    # What each worker counted of the datagrams handed on, by ID; nil for
    # one that has ended, or does not answer in `timeout` seconds, as one
    # whose server is not running yet.
    def stats(timeout: STATS_TIMEOUT)
      @controls.map do |control|
        reply = Ractor::Port.new #: Ractor::Port[Worker::Stats?]
        control.send([:stats, reply])
        timer = Thread.new do
          sleep timeout
          reply.send(nil)
        rescue Ractor::ClosedError
          nil
        end
        reply.receive
      rescue Ractor::ClosedError
        nil
      ensure
        timer&.kill
        reply&.close
      end
    end

    # Tells the workers to stop each time `stop` writes to the pipe.
    private def relay_stops(reader)
      loop do
        reader.wait_readable
        reader.read_nonblock(64, exception: false)
        stop_workers(@stop || Server::STOP_TIMEOUT)
      end
    rescue IOError
      nil
    end

    # A socket for each worker on `host` and `port`, the port the first was
    # given for those after it, and one for each preferred address the
    # first does not send from: the sockets of each worker, its first the
    # one on `port`.
    private def bind
      bound = [] #: Array[UDPSocket]
      begin
        first = UDP.open(@host, @port, reuse_port: true).tap { |socket| bound << socket }
        address = first.local_address
        @local_address = [UDP.unmapped(address.ip_address), address.ip_port]
        preferred = (@config.preferred_address&.values || []).reject { |preferred| UDP.covers?(address, preferred) }
        Array.new(@count) do |id|
          main = id.zero? ? first : UDP.open(@host, address.ip_port, reuse_port: true).tap { |socket| bound << socket }
          [main, *preferred.map { |host, port| UDP.open(host, port, reuse_port: true).tap { |socket| bound << socket } }]
        end
      rescue StandardError
        bound.each(&:close)
        raise
      end
    end

    # The Ractor of worker `id`: it makes its inbox and control port, tells
    # `out` of them, takes its sockets and the inboxes of all, and runs the
    # block with its Worker; the ports and sockets close when it is over.
    private def start(id, out, shared)
      Ractor.new(out, id, @count, @config, shared, @body, *@args) do |out, id, count, config, shared, body, *args|
        # What the block raises comes out of `run`, and is not reported here
        # as well.
        Thread.current.report_on_exception = false
        inbox = Ractor::Port.new
        control = Ractor::Port.new
        out.send([id, inbox, control])
        sockets, peers = Ractor.receive
        worker = Raiha::Next::Runtime::Worker.new(id:, count:, config:, sockets:, inbox:, control:, peers:, anti_replay: shared)
        begin
          body.call(worker, *args)
        ensure
          worker.close
          sockets.each { |socket| socket.close unless socket.closed? }
        end
      end
    end

    # Waits for the workers and the record; once one worker is over, or
    # the record, the workers left are told to stop.
    private def wait(ractors, record)
      failure = nil #: Exception?
      left = ractors.dup
      watched = record #: Ractor?
      stopping = false
      until left.empty?
        begin
          over, = Ractor.select(*left, *watched)
        rescue Ractor::RemoteError => error
          over = error.ractor
          failure ||= error.cause || error
        end
        if over.equal?(watched)
          watched = nil
          failure ||= Error::Stopped.new("the record of 0-RTT the workers share stopped")
        else
          left.delete(over)
        end
        stop_workers unless stopping
        stopping = true
      end
      raise failure if failure
      nil
    end

    private def stop_workers(timeout = Server::STOP_TIMEOUT)
      @controls.each do |control|
        control.send([:stop, timeout])
      rescue Ractor::ClosedError
        nil
      end
    end
  end
end
