# frozen_string_literal: true

require "raiha/next/http3_binding"
require_relative "next_client"

module RaihaInterop
  # The client of the http3 testcase on the next release of raiha: as
  # NextClient, over HTTP/3. Its HTTP/3 is joined to the connection by
  # HTTP3Binding, a GET for each path goes on a stream of its own, and
  # each response is saved once whole.
  class NextHTTP3Client < NextClient
    HTTP3 = Raiha::Next::HTTP3

    def alpn = ["h3"]

    private def connect(server_name, remote)
      @authority = server_name
      connection = super
      @http3 = HTTP3::Connection.client
      @binding = Raiha::Next::HTTP3Binding.new(connection, @http3)
      connection
    end

    # A turn of the application: what came back taken, and a GET for each
    # path while the server lets more streams open.
    private def step(connection)
      now = mono
      connection.each_event do |event|
        next if @binding.receive(event, now:)
        log("closed: #{event.error.inspect}") if event.is_a?(QUIC::Event::Closed)
      end
      @binding.flush(now:)
      @http3.each_event { |event| take(event) }
      request(connection) if connection.handshake_complete? && !(connection.closing? || connection.draining? || connection.closed?)
      @binding.flush(now:)
    end

    private def request(connection)
      while !@queue.empty? && (stream_id = connection.open_stream)
        path = @queue.shift
        @bodies[stream_id] = [path, "".b]
        @http3.send_request(stream_id, [[":method", "GET"], [":scheme", "https"], [":authority", @authority], [":path", path]], fin: true)
      end
    end

    private def take(event)
      case event
      when HTTP3::Event::Headers, HTTP3::Event::Data
        path, body = @bodies.fetch(event.stream_id)
        body << event.data if event.is_a?(HTTP3::Event::Data)
        save(path, body) if event.fin && @bodies.delete(event.stream_id)
      when HTTP3::Event::Reset then log("stream #{event.stream_id} reset with #{format("0x%x", event.error_code)}")
      end
    end
  end
end
