# frozen_string_literal: true

module Raiha::Next::Runtime
  # Runs an Endpoint on a UDP socket, with two fibers of its own under the
  # Fiber scheduler: the reader waits for datagrams and gives them to the
  # Endpoint; the runner runs the timers, lets the owner take its turn and
  # sends what there is to send, then waits until a timer is due or
  # something has changed.
  #
  # A call into the core never waits: the runtime gives it no I/O that could
  # yield to another fiber (a qlog goes to memory, and to its file after the
  # call), so each call runs to its end before any other fiber runs, and no
  # lock is held around it. The datagrams go out after it. The owner, a
  # client or a server of the runtime, is told of each Route but a response
  # to send, takes its turn each time round with a timer of its own, and is
  # told when the driver stops, with what failed when something did.
  class Driver
    attr_reader :endpoint, :failure

    def self.clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    def initialize(endpoint, udp, owner)
      @endpoint = endpoint
      @udp = udp
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
      Fiber.schedule { read }
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
      transmits = [] #: Array[Raiha::Next::QUIC::Transmit]
      @endpoint.each_transmit(now: Driver.clock) { |transmit| transmits << transmit }
      transmits.each { |transmit| @udp.send(transmit) }
    end

    # Stops the reader and the runner and closes the socket; the owner is
    # told.
    def stop
      return if @stopped
      @stopped = true
      changed
      @owner.stopped(@failure)
      @udp.close unless @udp.closed?
    end

    private def read
      until @stopped
        @udp.wait_readable
        responses = take(@udp.receive, Driver.clock)
        changed
        responses.each { |transmit| @udp.send(transmit) }
      end
    rescue IOError, Errno::EBADF
      raise unless @stopped
    rescue StandardError => error
      fail(error)
    end

    # Gives each datagram to the Endpoint, and each Route to the owner; the
    # responses the Endpoint sends itself.
    private def take(datagrams, now)
      responses = [] #: Array[Raiha::Next::QUIC::Transmit]
      datagrams.each do |data, from, ecn|
        route = @endpoint.receive(data, from:, ecn:, now:)
        route.is_a?(Raiha::Next::QUIC::Route::Respond) ? responses << route.transmit : (@owner.route(route, now) if route)
      end
      responses
    end

    private def run
      until @stopped
        turn(Driver.clock).each { |transmit| @udp.send(transmit) }
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
      deadline = @endpoint.next_timeout
      @endpoint.handle_timeout(now:) if deadline && deadline <= now
      @owner.turn(now)
      transmits = [] #: Array[Raiha::Next::QUIC::Transmit]
      @endpoint.each_transmit(now:) { |transmit| transmits << transmit }
      transmits
    end

    # Seconds until the next timer, nil for none.
    private def timeout
      deadline = [@endpoint.next_timeout, @owner.next_timeout].compact.min or return nil
      [deadline - Driver.clock, 0.0].max
    end

    private def fail(error)
      @failure ||= error
      stop
    end
  end
end
