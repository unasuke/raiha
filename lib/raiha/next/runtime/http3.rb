# frozen_string_literal: true

require_relative "../http3_binding"

module Raiha::Next::Runtime
  # The HTTP/3 the applications of the runtime use: a client over a Session
  # of Client.connect, and a server. HTTP/3 itself is the sans-IO
  # Raiha::Next::HTTP3, joined to the QUIC connection by HTTP3Binding.
  module HTTP3
    # The peer reset the request or the response a read or a write waits
    # on, with the HTTP/3 `error_code`.
    class StreamReset < Raiha::Next::Runtime::StreamReset; end

    # A response read whole: its status, its header fields without the
    # pseudo-header ones, its body and its trailer fields ([] for none).
    class Response < Data.define(:status, :headers, :body, :trailers); end

    # What the client keeps of a request until its response is read: the
    # response as it comes, and how the peer reset it, if it did.
    class Exchange
      attr_accessor :status, :headers, :trailers, :reset
      attr_reader :chunks

      def initialize
        @status = nil #: Integer?
        @headers = [] #: Array[[String, String]]
        @chunks = [] #: Array[String]
        @trailers = [] #: Array[[String, String]]
        @reset = nil #: Integer?
        @ended = false
      end

      def ended? = @ended

      def end!
        @ended = true
      end
    end

    # The client of HTTP/3 over a Session, which it attaches itself to. Each
    # request goes on a stream of its own, and the fiber that made it waits
    # for its response.
    class Client
      def initialize(session, authority: nil, settings: Raiha::Next::HTTP3::Settings.new)
        @session = session
        @http3 = Raiha::Next::HTTP3::Connection.client(settings:)
        @binding = Raiha::Next::HTTP3Binding.new(session.connection, @http3)
        @exchanges = {} #: Hash[Integer, Exchange]
        session.attach(self)
        @authority = authority || session.handshake&.server_name || raise(Error::Usage, "no authority to request from")
      end

      # The response to a GET of `path`, its body read whole.
      def get(path, headers: [])
        stream_id = start("GET", path, headers)
        exchange = @exchanges.fetch(stream_id)
        status = @session.wait_for do
          reset = exchange.reset and raise StreamReset.new(stream_id, reset)
          # HTTP/3 ends no response before its final status.
          exchange.status if exchange.ended?
        end
        Response.new(status:, headers: exchange.headers, body: exchange.chunks.join, trailers: exchange.trailers)
      ensure
        @exchanges.delete(stream_id) if stream_id
      end

      # The Session's protocol: the events of QUIC that are HTTP/3's.
      def take(event, now) = @binding.receive(event, now:)

      # The Session's protocol: HTTP/3 reads what came and has what it wrote
      # go out, and its events go to the exchanges they are of.
      def turn(now)
        @binding.flush(now:)
        @http3.each_event { |event| take_http3(event) }
        @binding.flush(now:)
      end

      # Sends the request on a new stream: its ID.
      private def start(method, path, headers, fin: true)
        stream_id = @session.open_stream_id
        @exchanges[stream_id] = Exchange.new
        pseudo = [[":method", method], [":scheme", "https"], [":authority", @authority], [":path", path]] #: Array[[String, String]]
        @http3.send_request(stream_id, pseudo + headers, fin:)
        @binding.flush(now: Driver.clock)
        @session.changed
        stream_id
      end

      private def take_http3(event)
        case event
        when Raiha::Next::HTTP3::Event::Headers
          exchange = @exchanges[event.stream_id] or return
          status = event.headers.find { |name, _| name == ":status" }&.last.to_i
          return if status.between?(100, 199)
          exchange.status = status
          exchange.headers = event.headers.reject { |name, _| name.start_with?(":") }
          exchange.end! if event.fin
        when Raiha::Next::HTTP3::Event::Data
          exchange = @exchanges[event.stream_id] or return
          exchange.chunks << event.data
          exchange.end! if event.fin
        when Raiha::Next::HTTP3::Event::Trailers
          exchange = @exchanges[event.stream_id] or return
          exchange.trailers = event.headers
          exchange.end!
        when Raiha::Next::HTTP3::Event::Reset
          @exchanges[event.stream_id]&.reset = event.error_code
        end
      end
    end
  end
end
