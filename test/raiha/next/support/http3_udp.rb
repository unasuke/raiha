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
end
