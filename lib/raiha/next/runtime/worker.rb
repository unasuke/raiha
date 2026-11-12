# frozen_string_literal: true

module Raiha::Next::Runtime
  # One of the workers of a server, as Workers gives each its own Ractor:
  # its ID of `count`, the sockets bound for it, its `inbox`, where other
  # workers hand on what came for its connections, the `control` port
  # Workers asks it things through, and `peers`, the inboxes of all the
  # workers by ID, its own included. The Retry token and stateless reset
  # keys are those every worker uses, so that each takes the tokens and
  # reads the connection IDs another issued, and `anti_replay` the record
  # of 0-RTT they share, so that each ClientHello's 0-RTT is taken once by
  # them all rather than once by each.
  #
  # A Ractor::Port waits for what comes without yielding to the Fiber
  # scheduler, so `listen` starts a thread of its own that waits on the
  # inbox and the control port: what is handed on goes into a queue the
  # driver takes from (`take`), up to QUEUE datagrams, past which the newest
  # is dropped; what comes to the control port goes to the block. `forward`
  # hands a datagram on to another worker, and never waits.
  class Worker
    # The most datagrams handed on that a worker keeps before taking them.
    QUEUE = 1024
    # What `close` sends the listening thread to end it.
    CLOSE = :close

    # What a worker counts of what it hands on and is handed: sent to
    # another worker, received from one, and dropped as the queue was full.
    Stats = Data.define(:id, :sent, :received, :dropped)

    attr_reader :id, :count, :sockets, :inbox, :control, :peers, :retry_token_key, :stateless_reset_key, :anti_replay

    def initialize(id:, count:, sockets:, inbox:, control:, peers:, retry_token_key:, stateless_reset_key:, anti_replay:)
      @id = id
      @anti_replay = anti_replay
      @retry_token_key = retry_token_key
      @stateless_reset_key = stateless_reset_key
      @count = count
      @sockets = sockets
      @inbox = inbox
      @control = control
      @peers = peers
      @queue = Thread::Queue.new
      @sent = 0
      @received = 0
      @dropped = 0
      @listener = nil #: Thread?
    end

    # Starts the thread that waits on the inbox and the control port: it
    # calls `changed` once a datagram handed on is queued, the block with
    # each message to the control port but a request for `stats`, which it
    # answers itself, and `failed` with what it raises, if anything. It ends
    # at the CLOSE `close` sends, as closing a port does not wake
    # Ractor.select.
    def listen(changed:, failed:, &control)
      raise Error::Usage, "the worker listens already" if @listener
      @listener = Thread.new do
        loop do
          port, message = Ractor.select(@inbox, @control)
          break if message == CLOSE && port.equal?(@control)
          port.equal?(@inbox) ? queue(message, changed) : answer(message, control)
        end
      rescue StandardError => error
        failed.call(error)
      end
      self
    end

    # Hands `forwarded`, [datagram, from, to, ecn, received_at], on to the
    # worker `worker`; one that has ended already gets nothing, and nothing
    # is answered for it.
    def forward(worker, forwarded)
      @peers.fetch(worker).send(Ractor.make_shareable(forwarded))
      @sent += 1
    rescue Ractor::ClosedError
      nil
    end

    # The datagrams handed on to this worker since the last `take`.
    def take
      taken = [] #: Array[forwarded]
      while (forwarded = @queue.pop(timeout: 0))
        taken << forwarded
      end
      taken
    end

    def stats = Stats.new(id: @id, sent: @sent, received: @received, dropped: @dropped)

    # Ends the listening thread and waits for it, then closes the inbox and
    # the control port, so that what other workers hand on from then is
    # dropped where it is sent.
    def close
      if (listener = @listener)
        @control.send(CLOSE) unless @control.closed?
        listener.join
      end
      [@inbox, @control].each(&:close)
      nil
    end

    private def queue(forwarded, changed)
      if @queue.size >= QUEUE
        @dropped += 1
        return
      end
      @received += 1
      @queue << forwarded
      changed.call
    end

    private def answer(message, control)
      return control.call(message) unless message.is_a?(Array) && message.first == :stats
      reply = message.fetch(1) #: Ractor::Port[Stats]
      reply.send(stats)
    rescue Ractor::ClosedError
      nil
    end
  end
end
