# frozen_string_literal: true

require "stringio"
require_relative "../../http3_binding"
require_relative "../../http3/session"

module Raiha::Runtime
  module Threaded
    # The HTTP/3 of the runtime on threads, as Runtime::HTTP3 is of the
    # runtime of fibers: a client over a Threaded::Session, and a server.
    # What waits for nothing it shares with the runtime of fibers: Exchange,
    # Response, StreamReset and Fields.
    module HTTP3
      StreamReset = Raiha::Runtime::HTTP3::StreamReset
      Response = Raiha::Runtime::HTTP3::Response
      Exchange = Raiha::Runtime::HTTP3::Exchange
      Fields = Raiha::Runtime::HTTP3::Fields

      # The body of a request at a server, or of a response at a client,
      # read as it comes.
      class Body
        def initialize(reader, stream_id)
          @reader = reader
          @stream_id = stream_id
        end

        # The next chunk once there is one, nil at the end.
        def read_chunk = @reader.read_chunk(@stream_id)

        # Each chunk until the end, waiting for each.
        def each
          while (chunk = read_chunk)
            yield chunk
          end
        end

        # All of what is left.
        def read
          data = "".b
          each { |chunk| data << chunk }
          data
        end
      end

      # A response as it comes, given to the block of Client#request once
      # its header section has.
      class ResponseStream
        attr_reader :status, :headers, :body

        def initialize(client, stream_id, exchange, status)
          @client = client
          @stream_id = stream_id
          @exchange = exchange
          @status = status
          @headers = exchange.headers
          @body = Body.new(client, stream_id)
        end

        # The trailer fields, once the body has been read to its end.
        def trailers = @exchange.trailers

        # Stops the request and its response with H3_REQUEST_CANCELLED.
        def cancel
          @client.cancel(@stream_id)
        end
      end

      # The client of HTTP/3 over a Threaded::Session, as the HTTP3::Client
      # of fibers is, to be used from several threads at once: each request
      # goes on a stream of its own, and the thread that made it writes its
      # body, reading it without the core lock, and waits for its response.
      # A Session of fibers is Error::Usage.
      class Client
        PIECE = Raiha::Runtime::HTTP3::Client::PIECE
        ALPN = Raiha::Runtime::HTTP3::Client::ALPN

        def initialize(session, authority: nil, settings: Raiha::HTTP3::Settings.new)
          raise Error::Usage, "a Session of the runtime on threads, not #{session.class}" unless session.is_a?(Threaded::Session)
          @session = session
          @settings = settings
          @tracer = (quic = session.tracer) && Raiha::HTTP3::Qlog::Tracer.new(quic)
          @http3 = Raiha::HTTP3::Connection.client(settings:, tracer: @tracer, remembered:)
          @binding = Raiha::HTTP3Binding.new(session.core, @http3)
          @exchanges = {} #: Hash[Integer, Exchange]
          session.attach(self, close_code: Raiha::HTTP3::ErrorCode::NO_ERROR)
          @authority = authority || session.server_name || raise(Error::Usage, "no authority to request from")
        end

        # The tickets the server gave, each an HTTP3::Session with the
        # server's SETTINGS; none until the SETTINGS have come.
        def tickets
          @session.synchronize do
            settings = @http3.peer_settings or next []
            @session.tickets.map { |quic| Raiha::HTTP3::Session.new(quic:, settings:) }
          end
        end

        # The response to a GET of `path`, its body read whole.
        def get(path, headers: [])
          request("GET", path, headers:)
        end

        # Sends a request, as HTTP3::Client#request of fibers does: the
        # response comes to the block, which runs without the core lock, as
        # a ResponseStream; with no block, it is read whole into a Response.
        def request(method, path, headers: [], body: nil, urgency: nil, incremental: nil)
          stream_id, exchange = start(method, path, headers + Fields.priority(urgency, incremental), fin: body.nil?)
          upload(stream_id, exchange, body) if body
          status = @session.wait_for(drain: true) do
            check(stream_id, exchange)
            exchange.status
          end
          return yield ResponseStream.new(self, stream_id, exchange, status) if block_given?
          Response.new(status:, headers: exchange.headers, body: Body.new(self, stream_id).read, trailers: exchange.trailers)
        ensure
          finish(stream_id, exchange) if stream_id && exchange
        end

        # The next chunk of the response on `stream_id` once there is one,
        # nil at its end; for Body.
        def read_chunk(stream_id)
          @session.synchronize do
            exchange = @exchanges[stream_id] or next nil
            chunk = @session.wait_for(drain: true) do
              check(stream_id, exchange)
              exchange.shift || (:end if exchange.ended?)
            end
            resume(stream_id, exchange) if exchange.paused && !exchange.full?
            chunk if chunk.is_a?(String)
          end
        end

        # Stops the request on `stream_id` and its response; for
        # ResponseStream.
        def cancel(stream_id)
          @session.synchronize do
            exchange = @exchanges[stream_id] or next
            next if exchange.ended? || exchange.reset
            @http3.cancel(stream_id)
            exchange.end!(dropped: true)
            @binding.resume(stream_id)
            flush
          end
        end

        # The Session's protocol, under the core lock: the events of QUIC
        # that are HTTP/3's.
        def take(event, now)
          case event
          when Raiha::QUIC::Event::ZeroRttRejected then zero_rtt_rejected
          when Raiha::QUIC::Event::Connected
            alpn = event.handshake.alpn
            unless alpn == ALPN
              @session.core.close(error_code: Raiha::HTTP3::ErrorCode::GENERAL_PROTOCOL_ERROR, reason: "ALPN #{alpn.inspect}, not h3", now:)
              return false
            end
          end
          @binding.receive(event, now:)
        end

        # The Session's protocol: a client's session runs out of no server's
        # time.
        def expire = nil

        # The Session's protocol, under the core lock.
        def turn(now)
          @binding.flush(now:)
          @http3.each_event { |event| take_http3(event) }
          @binding.flush(now:)
        end

        # Sends the request on a new stream, holding the core lock from when
        # the stream is open until its Exchange is kept, so that no event of
        # it is taken in between: its ID and the Exchange.
        private def start(method, path, headers, fin:)
          @session.synchronize do
            stream_id = @session.open_stream_id
            exchange = @exchanges[stream_id] = Exchange.new
            begin
              @http3.send_request(stream_id, Fields.request(method, @authority, path) + headers, fin:)
            rescue StandardError
              @exchanges.delete(stream_id)
              @session.core.stream_reset(stream_id, error_code: Raiha::HTTP3::ErrorCode::REQUEST_CANCELLED)
              @session.core.stream_stop_sending(stream_id, error_code: Raiha::HTTP3::ErrorCode::REQUEST_CANCELLED)
              @session.changed
              raise
            end
            flush
            [stream_id, exchange] #: [Integer, Exchange]
          end
        end

        private def remembered
          resumed = @session.resumed
          resumed.settings if resumed.is_a?(Raiha::HTTP3::Session) && @session.connection.zero_rtt_state == :pending
        end

        # Writes `body` as the request's content, read a piece at a time
        # without the core lock, and ends it.
        private def upload(stream_id, exchange, body)
          source = body.is_a?(String) ? StringIO.new(body) : body
          while (piece = source.read(PIECE))
            written = 0
            until written == piece.bytesize
              written += @session.wait_for do
                check(stream_id, exchange)
                stopped = exchange.stopped and return check_stopped(stream_id, stopped)
                taken = @http3.send_data(stream_id, piece.byteslice(written..) || "".b)
                next nil unless taken.positive?
                flush
                taken
              end
            end
          end
          @session.synchronize do
            @http3.send_data(stream_id, "".b, fin: true)
            flush
          end
        end

        private def check_stopped(stream_id, error_code)
          raise StreamReset.new(stream_id, error_code) unless error_code == Raiha::HTTP3::ErrorCode::NO_ERROR
        end

        private def check(stream_id, exchange)
          raise Raiha::QUIC::Error::ZeroRttRejected, "the request on stream #{stream_id} went in rejected 0-RTT" if exchange.rejected
          reset = exchange.reset and raise StreamReset.new(stream_id, reset)
        end

        # Lets go of what was kept of the request; a response not read to
        # its end is cancelled.
        private def finish(stream_id, exchange)
          @session.synchronize do
            next unless @exchanges[stream_id].equal?(exchange)
            cancel(stream_id)
            @exchanges.delete(stream_id)
          end
        end

        private def zero_rtt_rejected
          @exchanges.each_value { |exchange| exchange.rejected = true }
          @exchanges.clear
          @http3 = Raiha::HTTP3::Connection.client(settings: @settings, tracer: @tracer)
          @binding.restart(@http3)
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
            exchange = @exchanges[event.stream_id] or return
            status = Fields.status(event.headers) or return
            exchange.status = status
            exchange.headers = Fields.split(event.headers).last
            exchange.end! if event.fin
          when Raiha::HTTP3::Event::Data
            exchange = @exchanges[event.stream_id] or return
            exchange << event.data unless event.data.empty?
            exchange.end! if event.fin
            pause(event.stream_id, exchange) if exchange.full? && !exchange.paused
          when Raiha::HTTP3::Event::Trailers
            exchange = @exchanges[event.stream_id] or return
            exchange.trailers = event.headers
            exchange.end!
          when Raiha::HTTP3::Event::Reset then @exchanges[event.stream_id]&.reset = event.error_code
          when Raiha::HTTP3::Event::Stopped then @exchanges[event.stream_id]&.stopped = event.error_code
          end
        end

        private def pause(stream_id, exchange)
          exchange.paused = true
          @binding.pause(stream_id)
        end
      end
    end
  end
end
