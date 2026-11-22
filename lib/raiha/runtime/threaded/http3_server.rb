# frozen_string_literal: true

require_relative "http3"

module Raiha::Runtime
  module Threaded
    module HTTP3
      # The body of a response as the block of Request#respond writes it,
      # each write waiting while the stream holds back, and its trailer
      # fields, as the ResponseBody of fibers is.
      class ResponseBody
        attr_reader :trailers

        def initialize(server, stream_id, exchange)
          @server = server
          @stream_id = stream_id
          @exchange = exchange
          @trailers = [] #: Array[[String, String]]
          @closed = false
        end

        def write(data)
          closed!
          @server.write_body(@stream_id, @exchange, data.b)
          data.bytesize
        end

        def <<(data)
          write(data)
          self
        end

        def trailers=(fields)
          closed!
          @trailers = fields
        end

        # Ends the body, with the trailer fields given so far.
        def close
          return if @closed
          @closed = true
          @server.finish_body(@stream_id, @exchange, @trailers)
        end

        def closed? = @closed

        private def closed!
          raise Error::Usage, "the body of the response on stream #{@stream_id} has ended" if @closed
        end
      end

      # A request to the server of HTTP/3 on threads, given to the block of
      # Server#run in a thread of its own, as the Request of fibers is.
      class Request
        attr_reader :stream_id, :method, :path, :authority, :scheme, :protocol, :headers, :body

        def initialize(server, stream_id, exchange, headers)
          @server = server
          @stream_id = stream_id
          @exchange = exchange
          pseudo, @headers = Fields.split(headers)
          @method = pseudo.fetch(":method", "")
          @path = pseudo.fetch(":path", "")
          @authority = pseudo[":authority"]
          @scheme = pseudo[":scheme"]
          @protocol = pseudo[":protocol"]
          @body = Body.new(server, stream_id)
          @responded = false
          @marked_early = @headers.any? { |name, _| name == "early-data" }
        end

        # The trailer fields, once the body has been read to its end.
        def trailers = @exchange.trailers

        # Whether the request may be a replay of one on another connection,
        # as Runtime::HTTP3::Request#early_data? has it.
        def early_data? = @marked_early || @server.stream_early_data?(@stream_id)

        def responded? = @responded

        # Answers with `status`, `headers` and the whole of `body`; with a
        # block, the block writes the body to the ResponseBody it is given.
        def respond(status, headers = [], body = nil, &)
          raise ArgumentError, "a response's status is 200 to 599, not #{status.inspect}" unless status.is_a?(Integer) && status.between?(200, 599)
          raise Error::Usage, "the request on stream #{@stream_id} has its response already" if @responded
          @responded = true
          return @server.respond_with(@stream_id, @exchange, status, headers, &) if block_given?
          @server.respond(@stream_id, @exchange, status, headers, body)
        end

        # The priority of the response, `urgency:` and `incremental:`.
        def priority=(parameters)
          @server.prioritize(@stream_id, urgency: parameters[:urgency], incremental: parameters[:incremental])
        end
      end

      # The server of HTTP/3 of the runtime on threads: a Threaded::Server
      # whose sessions each have HTTP/3 attached, and whose block is given
      # each request in a thread of its own ("raiha-request"), as the
      # HTTP3::Server of fibers is. The threads of the requests take places
      # of `max_threads`, and the next request waits for one.
      #
      # A connection out of time to stop has the requests it had not yet
      # given to the block rejected, and those it had cancelled with
      # H3_REQUEST_CANCELLED: no thread is interrupted, so one waiting in a
      # read or a write raises StreamReset there, and one held up elsewhere
      # hears of it when it next touches its request.
      class Server
        def initialize(config:, tls_config:, keyring:, host: nil, port: nil, max_connections: Threaded::Server::MAX_CONNECTIONS,
          max_unvalidated: max_connections / 2, max_threads: Threaded::Server::MAX_THREADS, qlog_dir: nil,
          settings: Raiha::HTTP3::Settings.new, anti_replay: nil)
          @settings = settings
          @server = Threaded::Server.new(config:, tls_config:, keyring:, host:, port:, max_connections:, max_unvalidated:, max_threads:,
            qlog_dir:, anti_replay:, app_early_data_context: settings.early_data_context, stop_error_code: Raiha::HTTP3::ErrorCode::NO_ERROR)
        end

        def run(&handler)
          @server.run { |session| Serving.new(session, @settings).serve(&handler) }
        end

        def local_address = @server.local_address

        def stop(timeout: Threaded::Server::STOP_TIMEOUT)
          @server.stop(timeout:, error_code: Raiha::HTTP3::ErrorCode::NO_ERROR)
        end

        def reconfigure(...) = @server.reconfigure(...)
      end

      # The HTTP/3 of one connection of a Server: the requests as they come,
      # each to a thread of its own once it has a place. Each method holds
      # the core lock from its start to its end, but while it waits.
      class Serving
        LAST_REQUEST = Raiha::Runtime::HTTP3::Serving::LAST_REQUEST

        def initialize(session, settings)
          @session = session
          tracer = (quic = session.tracer) && Raiha::HTTP3::Qlog::Tracer.new(quic)
          @http3 = Raiha::HTTP3::Connection.server(settings:, tracer:)
          @binding = Raiha::HTTP3Binding.new(session.core, @http3)
          @exchanges = {} #: Hash[Integer, Exchange]
          # The requests whose header sections have come, not yet given to a
          # thread, with their header fields.
          @arrived = [] #: Array[[Integer, Array[[String, String]]]]
          # The threads of the requests given to the block and not over;
          # nil while one starts.
          @requests = {} #: Hash[Integer, Thread?]
          session.attach(self, close_code: Raiha::HTTP3::ErrorCode::NO_ERROR)
        end

        # Gives each request to the block in a thread of its own until the
        # connection closes, or until the server stops and the requests taken
        # are over.
        def serve(&handler)
          loop do
            arrived = place_for { @session.wait_for { @arrived.shift || (:stopping if @session.stopping?) } }
            return go_away(handler) if arrived == :stopping
            return unless arrived.is_a?(Array)
            start(handler, arrived)
          end
        rescue Raiha::QUIC::ClosedError
          nil
        end

        # The Session's protocol, under the core lock: the server is out of
        # time to stop. No thread is interrupted; what waits on a request
        # cancelled raises StreamReset once it looks again.
        def expire
          @arrived.each { |stream_id, _| @http3.cancel(stream_id, error_code: Raiha::HTTP3::ErrorCode::REQUEST_REJECTED) }
          @arrived.clear
          @requests.each_key do |stream_id|
            @http3.cancel(stream_id, error_code: Raiha::HTTP3::ErrorCode::REQUEST_CANCELLED)
            @exchanges[stream_id]&.reset = Raiha::HTTP3::ErrorCode::REQUEST_CANCELLED
          end
          @binding.flush(now: Driver.clock)
        end

        # The next chunk of the request on `stream_id` once there is one, nil
        # at its end; for Body.
        def read_chunk(stream_id)
          @session.synchronize do
            exchange = @exchanges[stream_id] or next nil
            chunk = @session.wait_for(drain: true) do
              reset = exchange.reset and raise StreamReset.new(stream_id, reset)
              exchange.shift || (:end if exchange.ended?)
            end
            resume(stream_id, exchange) if exchange.paused && !exchange.full?
            chunk if chunk.is_a?(String)
          end
        end

        # Sends the response on `stream_id`; for Request.
        def respond(stream_id, exchange, status, headers, body)
          @session.synchronize do
            send_header_section(stream_id, exchange, [[":status", status.to_s], *headers], fin: body.nil? || body.empty?)
            write(stream_id, exchange, body, fin: true) if body && !body.empty?
            exchange.answered = true
          end
        end

        # Sends the response on `stream_id`, its body written by the block,
        # which runs without the core lock; for Request.
        def respond_with(stream_id, exchange, status, headers)
          @session.synchronize { send_header_section(stream_id, exchange, [[":status", status.to_s], *headers], fin: false) }
          body = ResponseBody.new(self, stream_id, exchange)
          yield body
          body.close
        end

        # Ends the body of the response on `stream_id`, with `trailers` when
        # there are any; for ResponseBody.
        def finish_body(stream_id, exchange, trailers)
          @session.synchronize do
            if trailers.empty?
              writable(stream_id, exchange) { @http3.send_data(stream_id, "".b, fin: true) && true }
              flush
            else
              send_header_section(stream_id, exchange, trailers, fin: true)
            end
            exchange.answered = true
          end
        end

        # Writes `data` to the body of the response on `stream_id`; for
        # ResponseBody.
        def write_body(stream_id, exchange, data)
          @session.synchronize { write(stream_id, exchange, data, fin: false) }
        end

        # Whether a part of `stream_id` came in a 0-RTT packet; for Request.
        def stream_early_data?(stream_id) = @session.synchronize { @session.core.stream_early_data?(stream_id) }

        # For Request#priority=.
        def prioritize(stream_id, urgency:, incremental:)
          @session.synchronize do
            @http3.update_priority(stream_id, urgency:, incremental:)
            flush
          end
        end

        # The Session's protocol: the events of QUIC that are HTTP/3's.
        def take(event, now) = @binding.receive(event, now:)

        # The Session's protocol, under the core lock. The events of a turn
        # are all looked at before what they ask is done.
        def turn(now)
          @binding.flush(now:)
          events = [] #: Array[Raiha::HTTP3::Event::t]
          @http3.each_event { |event| events << event }
          events.each { |event| take_http3(event) }
          @binding.flush(now:)
        end

        # Takes a place of the threads for the next request, waiting for one
        # until the connection closes or the driver stops, then the block's
        # value, a request that has arrived; nil when no place was taken.
        # The place goes back unless the block gives a request.
        private def place_for
          return nil unless @session.threads.take { @session.ended? }
          arrived = begin
            yield
          rescue StandardError
            @session.threads.give_back
            raise
          end
          @session.threads.give_back unless arrived.is_a?(Array)
          arrived
        end

        # The request `arrived` in a thread of its own, on the place taken.
        # One whose thread cannot be started is cancelled with
        # H3_INTERNAL_ERROR, as one whose block raises in its response is,
        # and the connection goes on.
        private def start(handler, arrived)
          stream_id, headers = arrived
          @session.synchronize do
            exchange = @exchanges.fetch(stream_id)
            @requests[stream_id] = nil
            request = Request.new(self, stream_id, exchange, headers)
            @requests[stream_id] = @session.threads.start("raiha-request") { handle(handler, request) }
          rescue ThreadError
            @requests.delete(stream_id)
            @exchanges.delete(stream_id)
            @http3.cancel(stream_id, error_code: Raiha::HTTP3::ErrorCode::INTERNAL_ERROR)
            flush
          end
        end

        # The server is stopping: GOAWAY twice, with the requests that come in
        # between taken, each once it has a place, then the requests taken
        # let finish and what was sent let be acknowledged, until the server
        # is out of time.
        private def go_away(handler)
          begin
            @session.synchronize do
              @http3.goaway(LAST_REQUEST)
              flush
            end
          rescue Raiha::HTTP3::Error::Usage
            return
          end
          between = Driver.clock + 2 * @session.connection.stats.rtt
          while (arrived = place_for { @session.wait_for(deadline: between) { @arrived.shift } }).is_a?(Array)
            start(handler, arrived)
          end
          @session.synchronize do
            @http3.goaway
            flush
          end
          while (arrived = place_for { @session.wait_for { @arrived.shift || (:over if @requests.empty?) } }).is_a?(Array)
            start(handler, arrived)
          end
          deadline = @session.stop_deadline or return
          @session.wait_for(deadline:) { @session.core.stats.send_buffer_bytes.zero? || nil }
        end

        private def handle(handler, request)
          @session.unlocked!
          handler.call(request)
          request.respond(request.protocol ? 501 : 500) unless request.responded?
        rescue Raiha::QUIC::ClosedError, StreamReset
          nil
        rescue StandardError
          failed(request)
          raise
        ensure
          forget(request)
        end

        # The block raised: what can be told of it, told. A response gone
        # whole is not cut short for it.
        private def failed(request)
          return request.respond(500) unless request.responded?
          @session.synchronize do
            next if @exchanges[request.stream_id]&.answered
            @http3.cancel(request.stream_id, error_code: Raiha::HTTP3::ErrorCode::INTERNAL_ERROR)
            flush
          end
        rescue Raiha::QUIC::ClosedError, StreamReset
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
              # this thread again at once.
              next nil unless taken.positive?
              flush
              taken
            end
          end
        end

        # Calls the block until it gives something, waiting for room, unless
        # the client has reset the request or stopped the response, or the
        # server cancelled it out of time: that is looked at first, before
        # whether the connection has closed, as a cancel comes just before
        # the close and no thread is interrupted for it. A closed connection
        # is sent nothing. steep picks no overload of `wait` for a block
        # that gives T?.
        private def writable(stream_id, exchange) # steep:ignore
          @session.wait_for(drain: true) do
            stopped = exchange.stopped and raise StreamReset.new(stream_id, stopped)
            reset = exchange.reset and raise StreamReset.new(stream_id, reset)
            next nil if @session.core.close_reason
            yield
          end
        end

        # The request is over: what of its body has not come is not wanted.
        private def forget(request)
          stream_id = request.stream_id
          @session.synchronize do
            @exchanges.delete(stream_id)
            @requests.delete(stream_id)
            @http3.stop_reading(stream_id)
            @binding.resume(stream_id)
            # A stop waits for the requests to be over.
            @session.changed
          end
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
          when Raiha::HTTP3::Event::Headers
            return if @exchanges.key?(event.stream_id)
            exchange = @exchanges[event.stream_id] = Exchange.new
            exchange.end! if event.fin
            @arrived << [event.stream_id, event.headers]
          when Raiha::HTTP3::Event::Data
            exchange = @exchanges[event.stream_id] or return
            exchange << event.data unless event.data.empty?
            exchange.end! if event.fin
            if exchange.full? && !exchange.paused
              exchange.paused = true
              @binding.pause(event.stream_id)
            end
          when Raiha::HTTP3::Event::Trailers
            exchange = @exchanges[event.stream_id] or return
            exchange.trailers = event.headers
            exchange.end!
          when Raiha::HTTP3::Event::Reset then @exchanges[event.stream_id]&.reset = event.error_code
          when Raiha::HTTP3::Event::Stopped then @exchanges[event.stream_id]&.stopped = event.error_code
          end
        end
      end
    end
  end
end
