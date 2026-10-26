require "raiha/next/support/quic_udp"
require "raiha/next/support/http3_side"

# HTTP/3 of the next release of raiha on UDP sockets of the loopback
# interface, against another implementation run as a process of its own.
module NextHTTP3UDP
  include NextQUICUDP

  HTTP3 = Raiha::Next::HTTP3
  ALPN = ["h3"].freeze

  # A server's application: each request that has come whole is answered
  # with 200 and `body`, written as fast as HTTP/3 takes it; one reset or
  # stopped is not.
  class Server
    def initialize(server, body:)
      @server = server
      @body = body
      @sides = {}.compare_by_identity
      @left = {}
    end

    # A turn of the application.
    def step(now)
      @server.connections.each do |connection|
        side = @sides[connection] ||= NextHTTP3Side.new(connection, HTTP3::Connection.server)
        whole = []
        side.turn(now, ->(_, event) { take(side, event, whole) }) do
          whole.each { |stream_id| respond(side, stream_id) }
        end
      end
    end

    private def take(side, event, whole)
      case event
      when HTTP3::Event::Headers, HTTP3::Event::Data then whole << event.stream_id if event.fin
      when HTTP3::Event::Trailers then whole << event.stream_id
      when HTTP3::Event::Reset, HTTP3::Event::Stopped
        whole.delete(event.stream_id)
        @left.delete([side, event.stream_id])
      when HTTP3::Event::Writable then write(side, event.stream_id)
      end
    end

    private def respond(side, stream_id)
      side.http3.send_headers(stream_id, [[":status", "200"], ["content-length", @body.bytesize.to_s]])
      @left[[side, stream_id]] = @body
      write(side, stream_id)
    end

    private def write(side, stream_id)
      rest = @left[[side, stream_id]] or return
      rest = rest.byteslice(side.http3.send_data(stream_id, rest, fin: true)..) || "".b
      rest.empty? ? @left.delete([side, stream_id]) : @left[[side, stream_id]] = rest
    end
  end

  # A client's application: a GET of each of `paths` on `authority` goes
  # once QUIC has connected, and what comes back is kept by path, as
  # [status, body], once whole.
  class Client
    attr_reader :responses

    def initialize(connection, authority:, paths:)
      @connection = connection
      @side = NextHTTP3Side.new(connection, HTTP3::Connection.client)
      @authority = authority
      @paths = paths
      @streams = {}
      @statuses = {}
      @bodies = Hash.new { |bodies, stream_id| bodies[stream_id] = "".b }
      @responses = {}
    end

    # A turn of the application: whether every response has come whole.
    def step(now)
      @side.turn(now, ->(_, event) { take(event) }) do
        @paths.drop(@streams.size).each { |path| request(path) } if @connection.handshake_complete?
      end
      @responses.size == @paths.size
    end

    private def request(path)
      stream_id = @connection.open_stream or return
      @streams[stream_id] = path
      @side.http3.send_request(stream_id, [[":method", "GET"], [":scheme", "https"], [":authority", @authority], [":path", path]], fin: true)
    end

    private def take(event)
      case event
      when HTTP3::Event::Headers then @statuses[event.stream_id] = event.headers.to_h.fetch(":status")
      when HTTP3::Event::Data then @bodies[event.stream_id] << event.data
      else return
      end
      @responses[@streams.fetch(event.stream_id)] = [@statuses[event.stream_id], @bodies[event.stream_id]] if event.fin
    end
  end
end
