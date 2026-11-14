# frozen_string_literal: true

module Raiha::Runtime
  # Runs an Endpoint on a UDP socket, and on others besides, as a server's
  # at its preferred addresses, with fibers of its own under the Fiber
  # scheduler: a reader for each socket waits for datagrams and gives them
  # to the Endpoint; the runner runs the timers, lets the owner take its
  # turn and sends what there is to send, then waits until a timer is due
  # or something has changed. A Transmit goes from the socket its source
  # is on (UDP#sends_from?), the first when none is.
  #
  # A call into the core never waits: the runtime gives it no I/O that could
  # yield to another fiber (a qlog goes to memory, and to its file after the
  # call), so each call runs to its end before any other fiber runs, and no
  # lock is held around it. The datagrams go out after it. The owner, a
  # client or a server of the runtime, is told of each Route but a response
  # to send, takes its turn each time round with a timer of its own, and is
  # told when the driver stops, with what failed when something did.
  #
  # The driver of one of a server's workers hands on to its `worker` what
  # the Endpoint routes to another (Route::Foreign), with where it came from
  # and when, and in each turn gives the Endpoint what other workers handed
  # on to this one, as it came then.
  class Driver
    attr_reader :endpoint, :failure

    def self.clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    def initialize(endpoint, udp, owner, others: [], worker: nil)
      @endpoint = endpoint
      @worker = worker
      @udp = udp
      @udps = [udp, *others]
      @owner = owner
      # Only for the runner to wait on.
      @lock = Thread::Mutex.new
      @changed = Thread::ConditionVariable.new
      @dirty = false
      @stopped = false
      @failure = nil #: StandardError?
    end

    # Starts the reader and the runner, in fibers of the scheduler.
    def start
      raise Error::Usage, "the runtime waits through a Fiber scheduler; this thread has none" unless Fiber.scheduler
      @udps.each { |udp| Fiber.schedule { read(udp) } }
      Fiber.schedule { run }
      self
    end

    # Has the runner go round again, as after a call into the core.
    def changed
      @lock.synchronize do
        @dirty = true
        @changed.signal
      end
    end

    def stopped? = @stopped

    # Sends what there is to send now from the calling fiber, as the last
    # datagrams of a connection closed before the driver stops.
    def flush
      transmits = [] #: Array[Raiha::QUIC::Transmit]
      @endpoint.each_transmit(now: Driver.clock) { |transmit| transmits << transmit }
      transmits.each { |transmit| emit(transmit) }
    end

    # Stops the readers and the runner and closes the sockets; the owner is
    # told. The sockets close even when telling the owner fails.
    def stop
      return if @stopped
      @stopped = true
      changed
      @owner.stopped(@failure)
    ensure
      @udps.each { |udp| udp.close unless udp.closed? }
    end

    private def read(udp)
      until @stopped
        udp.wait_readable
        responses = take(udp.receive, Driver.clock)
        changed
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
        when Raiha::QUIC::Route::Foreign then @worker&.forward(route.worker, [data, from, to, ecn, now])
        when nil then nil
        else @owner.route(route, now)
        end
      end
      responses
    end

    # What other workers handed on to this one, given to the Endpoint as
    # it came then, never to be handed on again; the responses it sends.
    private def take_forwarded
      responses = [] #: Array[Raiha::QUIC::Transmit]
      @worker&.take&.each do |data, from, to, ecn, received_at|
        case (route = @endpoint.receive(data, from:, to:, ecn:, now: received_at, forwarded: true))
        when Raiha::QUIC::Route::Respond then responses << route.transmit
        when nil then nil
        else @owner.route(route, received_at)
        end
      end
      responses
    end

    private def run
      until @stopped
        turn(Driver.clock).each { |transmit| emit(transmit) }
        @lock.synchronize do
          @changed.wait(@lock, timeout) unless @dirty || @stopped
          @dirty = false
        end
      end
    rescue IOError, Errno::EBADF
      raise unless @stopped
    rescue StandardError => error
      fail(error)
    end

    # The timers of the Endpoint, the owner's turn, and what there is to
    # send after.
    private def turn(now)
      take_forwarded.each { |transmit| emit(transmit) }
      deadline = @endpoint.next_timeout
      @endpoint.handle_timeout(now:) if deadline && deadline <= now
      @owner.turn(now)
      transmits = [] #: Array[Raiha::QUIC::Transmit]
      @endpoint.each_transmit(now:) { |transmit| transmits << transmit }
      transmits
    end

    # Seconds until the next timer, nil for none.
    private def timeout
      deadline = [@endpoint.next_timeout, @owner.next_timeout].compact.min or return nil
      [deadline - Driver.clock, 0.0].max
    end

    # Sends `transmit` from the socket its source is on.
    private def emit(transmit)
      source = transmit.source
      (source && @udps.find { |udp| udp.sends_from?(source) } || @udp).send(transmit)
    end

    private def fail(error)
      @failure ||= error
      stop
    end
  end
end
