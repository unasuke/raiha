# frozen_string_literal: true

require_relative "http3"

module Raiha::Next::Runtime
  module HTTP3
    # The body of a response as the block of Request#respond writes it,
    # each write waiting while the stream holds back, and its trailer
    # fields.
    class ResponseBody
      attr_accessor :trailers

      def initialize(server, stream_id, exchange)
        @server = server
        @stream_id = stream_id
        @exchange = exchange
        @trailers = [] #: Array[[String, String]]
      end

      def write(data)
        @server.write_body(@stream_id, @exchange, data.b)
        data.bytesize
      end

      def <<(data)
        write(data)
        self
      end
    end

    # A request to the server of HTTP/3, given to the block of Server#run in
    # a fiber of its own: its pseudo-header fields, its header fields
    # without them, its body as it comes, and its trailer fields once the
    # body has been read. The block answers it with `respond`.
    class Request
      attr_reader :stream_id, :method, :path, :authority, :scheme, :protocol, :headers, :body

      def initialize(server, stream_id, exchange, headers)
        @server = server
        @stream_id = stream_id
        @exchange = exchange
        pseudo = headers.select { |name, _| name.start_with?(":") }.to_h
        @method = pseudo.fetch(":method", "")
        @path = pseudo.fetch(":path", "")
        @authority = pseudo[":authority"]
        @scheme = pseudo[":scheme"]
        @protocol = pseudo[":protocol"]
        @headers = headers.reject { |name, _| name.start_with?(":") }
        @body = Body.new(server, stream_id)
        @responded = false
      end

      # The trailer fields, once the body has been read to its end.
      def trailers = @exchange.trailers

      # 0-RTT comes with resumption, which this release does not have yet.
      def early_data? = false

      def responded? = @responded

      # Answers with `status`, `headers` and the whole of `body`, written as
      # the stream takes it; with a block, the block writes the body to the
      # ResponseBody it is given, and its trailer fields.
      def respond(status, headers = [], body = nil, &)
        # An interim response (1xx) has no way out yet.
        raise ArgumentError, "a response's status is 200 to 599, not #{status.inspect}" unless status.is_a?(Integer) && status.between?(200, 599)
        raise Error::Usage, "the request on stream #{@stream_id} has its response already" if @responded
        @responded = true
        return @server.respond_with(@stream_id, @exchange, status, headers, &) if block_given?
        @server.respond(@stream_id, @exchange, status, headers, body)
      end

      # The priority of the response, `urgency:` and `incremental:`: those
      # given override what the request asked (RFC 9218).
      def priority=(parameters)
        @server.prioritize(@stream_id, urgency: parameters[:urgency], incremental: parameters[:incremental])
      end
    end

    # The server of HTTP/3 of the runtime: a Runtime::Server whose
    # sessions each have HTTP/3 attached, and whose block is given each
    # request in a fiber of its own. A block that leaves a request with no
    # response has it answered with 500, or with 501 for an Extended
    # CONNECT, whose protocol it then does not take (RFC 9220). A block that
    # raises has its request answered with 500 before the response, and
    # reset with H3_INTERNAL_ERROR in the middle of it, and the exception
    # goes on to the scheduler; the other requests and the connection go
    # on.
    #
    # `stop` stops it as RFC 9114 "Connection Shutdown" has it: each
    # connection is sent a GOAWAY of the largest ID, then, twice the RTT
    # later, one of the first request it has not seen, from which HTTP/3
    # rejects requests with H3_REQUEST_REJECTED; the requests taken are let
    # finish, what was sent is let be acknowledged, and the connection
    # closes with H3_NO_ERROR. A connection out of time has the requests it
    # had not yet given to the block rejected, and those it had cancelled
    # with H3_REQUEST_CANCELLED, their fibers interrupted where they wait,
    # before it closes.
    #
    # Extended CONNECT (RFC 9220) is not offered unless `settings` offers
    # it: the runtime has no way yet to read or write the capsules of such a
    # stream, and a body of capsules would never read as data.
    class Server
      def initialize(config:, tls_config:, keyring:, host: "::", port: 443, max_connections: Raiha::Next::Runtime::Server::MAX_CONNECTIONS, qlog_dir: nil,
        settings: Raiha::Next::HTTP3::Settings.new)
        @settings = settings
        @server = Raiha::Next::Runtime::Server.new(config:, tls_config:, keyring:, host:, port:, max_connections:, qlog_dir:)
      end

      def run(&handler)
        @server.run { |session| Serving.new(session, @settings).serve(&handler) }
      end

      def local_address = @server.local_address

      def stop(timeout: Raiha::Next::Runtime::Server::STOP_TIMEOUT)
        @server.stop(timeout:, error_code: Raiha::Next::HTTP3::ErrorCode::NO_ERROR)
      end

      def reconfigure(...) = @server.reconfigure(...)
    end

    # The HTTP/3 of one connection of a Server: the requests as they come,
    # each to a fiber of its own.
    class Serving
      # The largest ID a server's GOAWAY gives, which only tells the client
      # to make no more requests.
      LAST_REQUEST = (1 << 62) - 4

      def initialize(session, settings)
        @session = session
        tracer = (quic = session.tracer) && Raiha::Next::HTTP3::Qlog::Tracer.new(quic)
        @http3 = Raiha::Next::HTTP3::Connection.server(settings:, tracer:)
        @binding = Raiha::Next::HTTP3Binding.new(session.connection, @http3)
        @exchanges = {} #: Hash[Integer, Exchange]
        # The requests whose header sections have come, not yet given to a
        # fiber, with their header fields.
        @arrived = [] #: Array[[Integer, Array[[String, String]]]]
        # The fibers of the requests given to the block and not over; nil
        # while one starts.
        @fibers = {} #: Hash[Integer, Fiber?]
        session.attach(self, close_code: Raiha::Next::HTTP3::ErrorCode::NO_ERROR)
      end

      # Gives each request to the block in a fiber of its own until the
      # connection closes, or until the server stops and the requests taken
      # are over.
      def serve(&handler)
        loop do
          arrived = @session.wait_for { @arrived.shift || (:stopping if @session.stopping?) }
          return go_away(handler) if arrived == :stopping
          start(handler, arrived)
        end
      rescue Raiha::Next::QUIC::ClosedError
        nil
      end

      # The Session's protocol: the server is out of time to stop.
      def expire
        @arrived.each { |stream_id, _| @http3.cancel(stream_id, error_code: Raiha::Next::HTTP3::ErrorCode::REQUEST_REJECTED) }
        @arrived.clear
        scheduler = Fiber.scheduler
        @fibers.each do |stream_id, fiber|
          @http3.cancel(stream_id, error_code: Raiha::Next::HTTP3::ErrorCode::REQUEST_CANCELLED)
          @exchanges[stream_id]&.reset = Raiha::Next::HTTP3::ErrorCode::REQUEST_CANCELLED
          next unless fiber&.alive? && scheduler.respond_to?(:fiber_interrupt)
          scheduler.fiber_interrupt(fiber, StreamReset.new(stream_id, Raiha::Next::HTTP3::ErrorCode::REQUEST_CANCELLED))
        end
        @binding.flush(now: Driver.clock)
      end

      # The next chunk of the request on `stream_id` once there is one, nil
      # at its end; for Body.
      def read_chunk(stream_id)
        exchange = @exchanges[stream_id] or return nil
        chunk = @session.wait_for(drain: true) do
          reset = exchange.reset and raise StreamReset.new(stream_id, reset)
          exchange.shift || (:end if exchange.ended?)
        end
        resume(stream_id, exchange) if exchange.paused && !exchange.full?
        chunk if chunk.is_a?(String)
      end

      # Sends the response on `stream_id`; for Request.
      def respond(stream_id, exchange, status, headers, body)
        send_header_section(stream_id, exchange, [[":status", status.to_s], *headers], fin: body.nil? || body.empty?)
        write(stream_id, exchange, body, fin: true) if body && !body.empty?
      end

      # Sends the response on `stream_id`, its body written by the block;
      # for Request.
      def respond_with(stream_id, exchange, status, headers)
        send_header_section(stream_id, exchange, [[":status", status.to_s], *headers], fin: false)
        body = ResponseBody.new(self, stream_id, exchange)
        yield body
        return send_header_section(stream_id, exchange, body.trailers, fin: true) unless body.trailers.empty?
        writable(stream_id, exchange) { @http3.send_data(stream_id, "".b, fin: true) && true }
        flush
      end

      # Writes `data` to the body of the response on `stream_id`; for
      # ResponseBody.
      def write_body(stream_id, exchange, data)
        write(stream_id, exchange, data, fin: false)
      end

      # For Request#priority=.
      def prioritize(stream_id, urgency:, incremental:)
        @http3.update_priority(stream_id, urgency:, incremental:)
        flush
      end

      # The Session's protocol: the events of QUIC that are HTTP/3's.
      def take(event, now) = @binding.receive(event, now:)

      # The Session's protocol. The events of a turn are all looked at before
      # what they ask is done, so a stream reset or stopped in it is written
      # to no more.
      def turn(now)
        @binding.flush(now:)
        events = [] #: Array[Raiha::Next::HTTP3::Event::t]
        @http3.each_event { |event| events << event }
        events.each { |event| take_http3(event) }
        @binding.flush(now:)
      end

      private def start(handler, arrived)
        stream_id, headers = arrived
        exchange = @exchanges.fetch(stream_id)
        # The fiber runs at once, and a request with nothing to wait for is
        # over before Fiber.schedule returns: it is known as there before it
        # starts, and not kept once over.
        @fibers[stream_id] = nil
        fiber = Fiber.schedule { handle(handler, Request.new(self, stream_id, exchange, headers)) }
        @fibers[stream_id] = fiber if @fibers.key?(stream_id)
      end

      # The server is stopping: GOAWAY twice, with the requests that come in
      # between taken, then the requests taken let finish and what was sent
      # let be acknowledged, until the server is out of time. A connection
      # whose control stream could not be opened has nothing to be told.
      private def go_away(handler)
        begin
          @http3.goaway(LAST_REQUEST)
        rescue Raiha::Next::HTTP3::Error::Usage
          return
        end
        flush
        between = Driver.clock + 2 * @session.connection.stats.rtt
        while (arrived = @session.wait_for(deadline: between) { @arrived.shift })
          start(handler, arrived)
        end
        @http3.goaway
        flush
        while (arrived = @session.wait_for { @arrived.shift || (:over if @fibers.empty?) }) != :over
          start(handler, arrived)
        end
        deadline = @session.stop_deadline or return
        @session.wait_for(deadline:) { @session.connection.stats.send_buffer_bytes.zero? || nil }
      end

      private def handle(handler, request)
        handler.call(request)
        request.respond(request.protocol ? 501 : 500) unless request.responded?
      rescue Raiha::Next::QUIC::ClosedError, StreamReset
        nil
      rescue StandardError
        failed(request)
        raise
      ensure
        forget(request)
      end

      # The block raised: what can be told of it, told.
      private def failed(request)
        return request.respond(500) unless request.responded?
        @http3.cancel(request.stream_id, error_code: Raiha::Next::HTTP3::ErrorCode::INTERNAL_ERROR)
        flush
      rescue Raiha::Next::QUIC::ClosedError, StreamReset
        nil
      end

      private def send_header_section(stream_id, exchange, fields, fin:)
        writable(stream_id, exchange) do
          @http3.send_headers(stream_id, fields, fin:)
          true
        end
        flush
      end

      # Writes all of `data`, as the stream takes it.
      private def write(stream_id, exchange, data, fin:)
        written = 0
        until written == data.bytesize
          written += writable(stream_id, exchange) do
            taken = @http3.send_data(stream_id, data.byteslice(written..) || "".b, fin:)
            # Nothing taken, nothing to send: waking the driver would wake
            # this fiber again at once.
            next nil unless taken.positive?
            flush
            taken
          end
        end
      end

      # Calls the block until it gives something, waiting for room, unless
      # the client has reset the request or stopped the response. steep
      # picks no overload of `wait` for a block that gives T?.
      private def writable(stream_id, exchange) # steep:ignore
        @session.wait_for do
          stopped = exchange.stopped and raise StreamReset.new(stream_id, stopped)
          reset = exchange.reset and raise StreamReset.new(stream_id, reset)
          yield
        end
      end

      # The request is over: what of its body has not come is not wanted.
      private def forget(request)
        stream_id = request.stream_id
        @exchanges.delete(stream_id)
        @fibers.delete(stream_id)
        @http3.stop_reading(stream_id)
        @binding.resume(stream_id)
        # A stop waits for the requests to be over.
        @session.changed
      end

      private def resume(stream_id, exchange)
        exchange.paused = false
        @binding.resume(stream_id)
        flush
      end

      private def flush
        @binding.flush(now: Driver.clock)
        @session.changed
      end

      private def take_http3(event)
        case event
        when Raiha::Next::HTTP3::Event::Headers
          return if @exchanges.key?(event.stream_id)
          exchange = @exchanges[event.stream_id] = Exchange.new
          exchange.end! if event.fin
          @arrived << [event.stream_id, event.headers]
        when Raiha::Next::HTTP3::Event::Data
          exchange = @exchanges[event.stream_id] or return
          exchange << event.data unless event.data.empty?
          exchange.end! if event.fin
          if exchange.full? && !exchange.paused
            exchange.paused = true
            @binding.pause(event.stream_id)
          end
        when Raiha::Next::HTTP3::Event::Trailers
          exchange = @exchanges[event.stream_id] or return
          exchange.trailers = event.headers
          exchange.end!
        when Raiha::Next::HTTP3::Event::Reset then @exchanges[event.stream_id]&.reset = event.error_code
        when Raiha::Next::HTTP3::Event::Stopped then @exchanges[event.stream_id]&.stopped = event.error_code
        end
      end
    end
  end
end
