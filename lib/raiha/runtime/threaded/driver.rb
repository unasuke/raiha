# frozen_string_literal: true

module Raiha::Runtime
  module Threaded
    # Runs an Endpoint on a UDP socket, and on others besides, as the
    # Driver of fibers does, with threads of its own: a reader for each
    # socket ("raiha-reader") waits for datagrams and gives them to the
    # Endpoint, and the runner ("raiha-runner") runs the timers, lets the
    # owner take its turn and sends what there is to send, then waits until
    # a timer is due or something has changed.
    #
    # The core lock, a Monitor, is held around each call into the core,
    # the Endpoint's and those of the owner, which call into its
    # connections; what other threads call into the core, a Session's
    # methods, takes it too, with `synchronize`, and waits on a condition
    # of it (`new_cond`). No I/O is done under it: a reader waits for and
    # receives datagrams without it, and the Transmits taken under it go
    # once it is let go, each socket sending one at a time. A `flush` under
    # the lock, from the owner's turn, leaves what it took for the runner
    # to send after the turn, before what the turn has to send; so does a
    # `stop` under it the closing of the sockets.
    #
    # The owner is told of each Route but a response to send, takes its
    # turn each time round with a timer of its own, and is told when the
    # driver stops, with what failed when something did, all under the
    # lock; it writes its traces with `flush_traces`, called without the
    # lock after each turn and once the driver has stopped.
    class Driver
      attr_reader :endpoint

      def self.clock = Raiha::Runtime::Driver.clock

      def initialize(endpoint, udp, owner, others: [])
        @endpoint = endpoint
        @udp = udp
        @udps = [udp, *others]
        @owner = owner
        @core = Monitor.new
        # Only for the runner to wait on.
        @changed = @core.new_cond
        @dirty = false
        @stopped = false
        @failure = nil #: StandardError?
        # What a flush under the lock took, for the runner to send.
        @queued = [] #: Array[Raiha::QUIC::Transmit]
        @sending = @udps.to_h { |socket| [socket, Thread::Mutex.new] } #: Hash[UDP, Thread::Mutex]
        @readers = [] #: Array[Thread]
        @runner = nil #: Thread?
      end

      # Starts the reader of each socket and the runner, each a thread.
      def start
        @readers = @udps.map do |udp|
          Thread.new { read(udp) }.tap { |thread| thread.name = "raiha-reader" }
        end
        @runner = Thread.new { run }.tap { |thread| thread.name = "raiha-runner" }
        self
      end

      # Holds the core lock around the block, as whatever calls into the
      # core does; the block's value.
      def synchronize(&) = @core.synchronize(&)

      # A condition of the core lock, to wait on while holding it.
      def new_cond = @core.new_cond

      # Whether this thread holds the core lock.
      def mon_owned? = @core.mon_owned?

      # What failed in the driver, if anything did.
      def failure = @core.synchronize { @failure }

      # Has the runner go round again, as after a call into the core.
      def changed
        @core.synchronize do
          @dirty = true
          @changed.signal
        end
      end

      def stopped? = @core.synchronize { @stopped }

      # Sends what there is to send now, as the last datagrams of a
      # connection closed before the driver stops: from this thread once
      # the lock is let go, or, when this thread holds the lock, from the
      # runner after its turn.
      def flush
        if @core.mon_owned?
          @endpoint.each_transmit(now: Driver.clock) { |transmit| @queued << transmit }
          changed
          return
        end
        transmits = [] #: Array[Raiha::QUIC::Transmit]
        @core.synchronize { @endpoint.each_transmit(now: Driver.clock) { |transmit| transmits << transmit } }
        transmits.each { |transmit| emit(transmit) }
      end

      # Stops the readers and the runner and closes the sockets; the owner
      # is told once, under the lock. The sockets close even when telling
      # the owner fails: while the runner runs, it closes them once it has
      # sent what is left, a flush's from the turn that stopped it say;
      # otherwise they close at once, and the owner writes its traces.
      def stop
        @core.synchronize do
          next if @stopped
          @stopped = true
          @changed.signal
          @owner.stopped(@failure)
        end
      ensure
        unless @runner&.alive?
          close
          @owner.flush_traces unless @core.mon_owned?
        end
      end

      # Waits for the readers and the runner to end, once stopped.
      def join
        [*@readers, @runner].each { |thread| thread&.join }
        nil
      end

      private def read(udp)
        until @stopped
          udp.wait_readable
          datagrams = udp.receive
          now = Driver.clock
          responses = @core.synchronize do
            next [] if @stopped
            taken = take(datagrams, now)
            @dirty = true
            @changed.signal
            taken
          end
          responses.each { |transmit| emit(transmit) }
        end
      rescue IOError, Errno::EBADF
        raise unless @stopped
      rescue StandardError => error
        fail(error)
      end

      # Gives each datagram to the Endpoint, and each Route to the owner; the
      # responses the Endpoint sends itself.
      private def take(datagrams, now)
        responses = [] #: Array[Raiha::QUIC::Transmit]
        datagrams.each do |data, from, to, ecn|
          case (route = @endpoint.receive(data, from:, to:, ecn:, now:))
          when Raiha::QUIC::Route::Respond then responses << route.transmit
          when nil then nil
          else @owner.route(route, now)
          end
        end
        responses
      end

      private def run
        until @stopped
          transmits = @core.synchronize { turn(Driver.clock) }
          transmits.each { |transmit| emit(transmit) }
          @owner.flush_traces
          @core.synchronize do
            @changed.wait(timeout) unless @dirty || @stopped
            @dirty = false
          end
        end
      rescue IOError, Errno::EBADF
        raise unless @stopped
      rescue StandardError => error
        fail(error)
      ensure
        last
      end

      # The timers of the Endpoint, the owner's turn, and what there is to
      # send after, what a flush in the turn took first.
      private def turn(now)
        deadline = @endpoint.next_timeout
        @endpoint.handle_timeout(now:) if deadline && deadline <= now
        @owner.turn(now)
        @endpoint.each_transmit(now:) { |transmit| @queued << transmit }
        transmits = @queued
        @queued = []
        transmits
      end

      # What a flush or a stop under the lock left for the runner, once it
      # has stopped: what was taken goes, the sockets close, and the owner
      # writes its traces.
      private def last
        return unless @stopped
        transmits = @core.synchronize do
          taken = @queued
          @queued = []
          taken
        end
        begin
          transmits.each { |transmit| emit(transmit) }
        rescue IOError, Errno::EBADF
          nil
        end
        close
        @owner.flush_traces
      end

      # Seconds until the next timer, nil for none.
      private def timeout
        deadline = [@endpoint.next_timeout, @owner.next_timeout].compact.min or return nil
        [deadline - Driver.clock, 0.0].max
      end

      # Sends `transmit` from the socket its source is on, one Transmit at a
      # time on each socket, as UDP#send keeps what it learns of the OS.
      private def emit(transmit)
        source = transmit.source
        udp = source && @udps.find { |socket| socket.sends_from?(source) } || @udp
        @sending.fetch(udp).synchronize { udp.send(transmit) }
      end

      private def close
        @udps.each { |udp| udp.close unless udp.closed? }
      end

      private def fail(error)
        @core.synchronize { @failure ||= error }
        stop
      end
    end
  end
end
