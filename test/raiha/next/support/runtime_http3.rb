require "raiha/next/support/runtime_owner"

# HTTP/3 for the tests of the runtime's HTTP/3 client: TLS settings with
# "h3" for ALPN, and a server's HTTP/3 attached to a Session of a
# Runtime::Server that answers each request whole with 200 and the body of
# its path, or 404. "/early" is answered with a 103 first, "/trailers" with
# trailer fields after its body, "/echo" with the request's body,
# "/priority" with its priority field, and "/reset" is cancelled.
module NextRuntimeHTTP3
  include NextRuntimeOwner

  HTTP3 = Raiha::Next::HTTP3
  H3 = ["h3"].freeze

  class Answerer
    HTTP3 = Raiha::Next::HTTP3
    TRAILERS = [["x-checksum", "abc"]].freeze

    def initialize(session, bodies)
      @bodies = bodies
      @http3 = HTTP3::Connection.server
      @binding = Raiha::Next::HTTP3Binding.new(session.connection, @http3)
      @requests = {}
      @left = {}
      session.attach(self)
    end

    def take(event, now) = @binding.receive(event, now:)

    # The events of a turn are all looked at before any is answered: a
    # stream the client stopped or reset in it is written to no more.
    def turn(now)
      @binding.flush(now:)
      events = []
      @http3.each_event { |event| events << event }
      events.grep(HTTP3::Event::Reset).each { |event| @requests.delete(event.stream_id) }
      events.grep(HTTP3::Event::Stopped).each { |event| @left.delete(event.stream_id) && @requests.delete(event.stream_id) }
      stopped = events.grep(HTTP3::Event::Stopped).map(&:stream_id)
      events.each { |event| answer(event) unless stopped.include?(event.respond_to?(:stream_id) && event.stream_id) }
      @binding.flush(now:)
    end

    private def answer(event)
      case event
      when HTTP3::Event::Headers
        fields = event.headers.to_h
        @requests[event.stream_id] = { path: fields.fetch(":path"), priority: fields["priority"], body: "".b }
        respond(event.stream_id) if event.fin
      when HTTP3::Event::Data
        @requests[event.stream_id]&.fetch(:body)&.<<(event.data)
        respond(event.stream_id) if event.fin
      when HTTP3::Event::Trailers then respond(event.stream_id)
      when HTTP3::Event::Writable then write(event.stream_id)
      when HTTP3::Event::Reset, HTTP3::Event::Stopped then @left.delete(event.stream_id)
      end
    end

    private def respond(stream_id)
      request = @requests.delete(stream_id) or return
      path = request.fetch(:path)
      return @http3.cancel(stream_id) if path == "/reset"
      body = case path
      when "/echo" then request.fetch(:body)
      when "/priority" then request.fetch(:priority) || "none"
      else @bodies[path]
      end
      return @http3.send_headers(stream_id, [[":status", "404"]], fin: true) unless body
      @http3.send_headers(stream_id, [[":status", "103"], ["link", "</style.css>"]]) if path == "/early"
      @http3.send_headers(stream_id, [[":status", "200"], ["content-length", body.bytesize.to_s]])
      @left[stream_id] = [body, path == "/trailers"]
      write(stream_id)
    end

    private def write(stream_id)
      left = @left[stream_id] or return
      rest, trailers = left
      rest = rest.byteslice(@http3.send_data(stream_id, rest, fin: !trailers)..) || "".b
      return @left[stream_id] = [rest, trailers] unless rest.empty?
      @left.delete(stream_id)
      @http3.send_headers(stream_id, TRAILERS, fin: true) if trailers
    end
  end

  def h3_server_config = NextTLSPair.server_config(profile: TLS::Profile::QUIC, alpn: H3, registry: REGISTRY)

  def h3_client_config = NextTLSPair.client_config(profile: TLS::Profile::QUIC, alpn: H3, registry: REGISTRY)

  # A Runtime::Server on a free port answering with `bodies`, for the block,
  # which is given its port and the server's sessions as they come.
  def answering(bodies)
    sessions = []
    tls = h3_server_config
    server = Raiha::Next::Runtime::Server.new(config: QUIC::Config.new, tls_config: tls, keyring: server_keyring(config: tls),
      host: "127.0.0.1", port: 0)
    running = Fiber.schedule do
      server.run do |session|
        sessions << session
        Answerer.new(session, bodies)
        sleep 0.01 until session.closed?
      end
    end
    sleep 0.01 until server.local_address
    yield server.local_address.fetch(1), sessions
  ensure
    server&.stop(timeout: 1)
    sleep 0.01 while running&.alive?
  end

  # A Session of a client connected to `port` with "h3", for the block.
  def h3_connect(port, &)
    tls = h3_client_config
    Raiha::Next::Runtime::Client.connect("127.0.0.1", port, config: QUIC::Config.new, tls_config: tls, keyring: client_keyring(config: tls),
      server_name: "localhost", &)
  end
end
