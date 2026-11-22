# frozen_string_literal: true

require "stringio"
require_relative "../http3_binding"
require_relative "../http3/session"
require_relative "http3_fields"

module Raiha::Runtime
  # The HTTP/3 the applications of the runtime use: a client over a Session
  # of Client.connect, and a server. HTTP/3 itself is the sans-IO
  # Raiha::HTTP3, joined to the QUIC connection by HTTP3Binding.
  module HTTP3
    # The peer reset the request or the response a read or a write waits
    # on, with the HTTP/3 `error_code`.
    class StreamReset < Raiha::Runtime::StreamReset; end

    # A response read whole: its status, its header fields without the
    # pseudo-header ones, its body and its trailer fields ([] for none).
    class Response < Data.define(:status, :headers, :body, :trailers); end

    # What the client keeps of a request until its response is read: the
    # response as it comes, its body as far as the application has not read
    # it, how the peer reset the response or stopped the request, and
    # whether the server rejected the 0-RTT it went in. The server keeps the
    # same of a request's body until the request is over, and whether its
    # response has gone whole.
    class Exchange
      # The most of a body kept unread before its stream is read no more,
      # so that the peer's flow control holds the rest back. What one read
      # of the stream takes comes on top, as much as the stream's flow
      # control window lets the peer send. What is unread is kept in one
      # String, however small the DATA frames it came in.
      MAX_UNREAD = 256 * 1024

      attr_accessor :status, :headers, :trailers, :reset, :stopped, :paused, :answered, :rejected
      attr_reader :unread

      def initialize
        @status = nil #: Integer?
        @headers = [] #: Array[[String, String]]
        @data = "".b
        @unread = 0
        @trailers = [] #: Array[[String, String]]
        @reset = nil #: Integer?
        @stopped = nil #: Integer?
        @paused = false
        @answered = false
        @rejected = false
        @ended = false
      end

      def <<(chunk)
        @data << chunk
        @unread += chunk.bytesize
        self
      end

      # What of the body has come and is not read yet, nil when nothing has.
      def shift
        return nil if @data.empty?
        data = @data
        @data = "".b
        @unread = 0
        data
      end

      def full? = @unread >= MAX_UNREAD

      def ended? = @ended

      # The response has ended; with `dropped`, what was not read goes.
      def end!(dropped: false)
        @ended = true
        return unless dropped
        @data = "".b
        @unread = 0
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

    # The body of a response, read as it comes.
    class Body
      def initialize(client, stream_id)
        @client = client
        @stream_id = stream_id
      end

      # The next chunk once there is one, nil at the end.
      def read_chunk = @client.read_chunk(@stream_id)

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

    # The client of HTTP/3 over a Session, which it attaches itself to. Each
    # request goes on a stream of its own, and the fiber that made it writes
    # its body and waits for its response. A body is a String or what reads
    # as an IO does, and goes as the peer's flow control lets it; the body
    # of a response is read no further than MAX_UNREAD bytes ahead of the
    # application.
    #
    # When the server rejects 0-RTT, each request that went in it raises
    # QUIC::Error::ZeroRttRejected, and HTTP/3 starts over with no SETTINGS
    # remembered. Sending one again is the application's (RFC 9846 "Replay
    # Attacks on 0-RTT"). A connection whose handshake chose another ALPN
    # than "h3", which a client offering more may be given once its 0-RTT
    # of "h3" was rejected, closes with H3_GENERAL_PROTOCOL_ERROR.
    class Client
      # The most of a request's body read from it at a time.
      PIECE = 64 * 1024
      ALPN = "h3"

      def initialize(session, authority: nil, settings: Raiha::HTTP3::Settings.new)
        # One of threads would be called into with no lock taken.
        raise Error::Usage, "a Session of the runtime on fibers, not #{session.class}" if session.is_a?(Threaded::Session)
        @session = session
        @settings = settings
        @tracer = (quic = session.tracer) && Raiha::HTTP3::Qlog::Tracer.new(quic)
        @http3 = Raiha::HTTP3::Connection.client(settings:, tracer: @tracer, remembered:)
        @binding = Raiha::HTTP3Binding.new(session.connection, @http3)
        @exchanges = {} #: Hash[Integer, Exchange]
        session.attach(self, close_code: Raiha::HTTP3::ErrorCode::NO_ERROR)
        @authority = authority || session.server_name || raise(Error::Usage, "no authority to request from")
      end

      # The tickets the server gave, each an HTTP3::Session with the server's
      # SETTINGS, for Client.connect(session:); none until the SETTINGS have
      # come, which may be after the tickets (RFC 9114 "Initialization"). As
      # Session#tickets, the newest last.
      def tickets
        settings = @http3.peer_settings or return []
        @session.tickets.map { |quic| Raiha::HTTP3::Session.new(quic:, settings:) }
      end

      # The response to a GET of `path`, its body read whole.
      def get(path, headers: [])
        request("GET", path, headers:)
      end

      # Sends a request, with `body` when there is one, and its priority
      # (RFC 9218) as the `priority` field when `urgency` (0 to 7) or
      # `incremental` is given. The response comes to the block as a
      # ResponseStream, and the block's value is returned; with no block, the
      # response is read whole into a Response. A response the block left
      # unread is cancelled.
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

      # The next chunk of the response on `stream_id` once there is one, nil
      # at its end; for Body.
      def read_chunk(stream_id)
        exchange = @exchanges[stream_id] or return nil
        chunk = @session.wait_for(drain: true) do
          check(stream_id, exchange)
          exchange.shift || (:end if exchange.ended?)
        end
        resume(stream_id, exchange) if exchange.paused && !exchange.full?
        chunk if chunk.is_a?(String)
      end

      # Stops the request on `stream_id` and its response; for
      # ResponseStream.
      def cancel(stream_id)
        exchange = @exchanges[stream_id] or return
        return if exchange.ended? || exchange.reset
        @http3.cancel(stream_id)
        exchange.end!(dropped: true)
        @binding.resume(stream_id)
        flush
      end

      # The Session's protocol: the events of QUIC that are HTTP/3's.
      def take(event, now)
        case event
        when Raiha::QUIC::Event::ZeroRttRejected then zero_rtt_rejected
        when Raiha::QUIC::Event::Connected
          alpn = event.handshake.alpn
          unless alpn == ALPN
            @session.connection.close(error_code: Raiha::HTTP3::ErrorCode::GENERAL_PROTOCOL_ERROR, reason: "ALPN #{alpn.inspect}, not h3",
              now:)
            return false
          end
        end
        @binding.receive(event, now:)
      end

      # The Session's protocol: a client's session runs out of no server's
      # time.
      def expire = nil

      # The Session's protocol: HTTP/3 reads what came and has what it wrote
      # go out, and its events go to the exchanges they are of.
      def turn(now)
        @binding.flush(now:)
        @http3.each_event { |event| take_http3(event) }
        @binding.flush(now:)
      end

      # Sends the request on a new stream: its ID and the Exchange kept of it,
      # which a rejected 0-RTT may have let go of by the time it is looked
      # for. A request HTTP/3 does not take, after the server's GOAWAY or
      # with header fields it finds malformed, gives its stream up both
      # ways.
      private def start(method, path, headers, fin:)
        stream_id = @session.open_stream_id
        exchange = @exchanges[stream_id] = Exchange.new
        begin
          @http3.send_request(stream_id, Fields.request(method, @authority, path) + headers, fin:)
        rescue StandardError
          @exchanges.delete(stream_id)
          @session.connection.stream_reset(stream_id, error_code: Raiha::HTTP3::ErrorCode::REQUEST_CANCELLED)
          @session.connection.stream_stop_sending(stream_id, error_code: Raiha::HTTP3::ErrorCode::REQUEST_CANCELLED)
          @session.changed
          raise
        end
        flush
        [stream_id, exchange] #: [Integer, Exchange]
      end

      # While 0-RTT goes, the SETTINGS of the HTTP3::Session the connection
      # resumes, which the requests keep to until the server's come.
      private def remembered
        resumed = @session.resumed
        resumed.settings if resumed.is_a?(Raiha::HTTP3::Session) && @session.connection.zero_rtt_state == :pending
      end

      # Writes `body` as the request's content, as the stream takes it, and
      # ends it. A peer that stops the request with H3_NO_ERROR wants no
      # more of it and answers all the same (RFC 9114 "Request
      # Cancellation and Rejection").
      private def upload(stream_id, exchange, body)
        source = body.is_a?(String) ? StringIO.new(body) : body
        while (piece = source.read(PIECE))
          written = 0
          until written == piece.bytesize
            written += @session.wait_for do
              check(stream_id, exchange)
              stopped = exchange.stopped and return check_stopped(stream_id, stopped)
              taken = @http3.send_data(stream_id, piece.byteslice(written..) || "".b)
              # Nothing taken, nothing to send: waking the driver would wake
              # this fiber again at once.
              next nil unless taken.positive?
              flush
              taken
            end
          end
        end
        @http3.send_data(stream_id, "".b, fin: true)
        flush
      end

      private def check_stopped(stream_id, error_code)
        raise StreamReset.new(stream_id, error_code) unless error_code == Raiha::HTTP3::ErrorCode::NO_ERROR
      end

      # What the server did to the request, raised where the fiber that made
      # it waits.
      private def check(stream_id, exchange)
        raise Raiha::QUIC::Error::ZeroRttRejected, "the request on stream #{stream_id} went in rejected 0-RTT" if exchange.rejected
        reset = exchange.reset and raise StreamReset.new(stream_id, reset)
      end

      # Lets go of what was kept of the request; a response not read to its
      # end is cancelled. A request of rejected 0-RTT has nothing kept, and
      # its stream's ID may be another's now.
      private def finish(stream_id, exchange)
        return unless @exchanges[stream_id].equal?(exchange)
        cancel(stream_id)
        @exchanges.delete(stream_id)
      end

      # The server rejected 0-RTT: the streams of the requests are gone, and
      # HTTP/3's, and it starts over with a layer that remembers nothing.
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
