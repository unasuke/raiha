# frozen_string_literal: true

require "raiha/http3_binding"
require_relative "next_server"

module RaihaInterop
  # The server of the http3 testcase on the next release of raiha: as
  # NextServer, over HTTP/3. Each connection's HTTP/3 is joined to it by
  # HTTP3Binding, and each request is answered with 200 and the file of
  # its path under WWW, written as fast as HTTP/3 takes it.
  class NextHTTP3Server < NextServer
    HTTP3 = Raiha::HTTP3

    def initialize(...)
      super
      # The HTTP/3 of each connection, with its binding, and what is left
      # to write of each response by [HTTP/3 connection, stream ID].
      @http3 = {}.compare_by_identity
      @left = {}
    end

    def alpn = ["h3"]

    private def serve(connection)
      http3, binding = @http3[connection] ||= HTTP3::Connection.server.then { [_1, Raiha::HTTP3Binding.new(connection, _1)] }
      now = mono
      connection.each_event do |event|
        next if binding.receive(event, now:)
        log("closed: #{event.error.inspect}") if event.is_a?(QUIC::Event::Closed)
      end
      binding.flush(now:)
      http3.each_event { |event| take(http3, event) }
      binding.flush(now:)
    end

    private def take(http3, event)
      case event
      when HTTP3::Event::Headers
        body = file(event.headers.to_h[":path"])
        http3.send_headers(event.stream_id, [[":status", "200"], ["content-length", body.bytesize.to_s]])
        @left[[http3, event.stream_id]] = body
        write(http3, event.stream_id)
      when HTTP3::Event::Writable then write(http3, event.stream_id)
      when HTTP3::Event::Reset, HTTP3::Event::Stopped then @left.delete([http3, event.stream_id])
      end
    end

    private def write(http3, stream_id)
      rest = @left[[http3, stream_id]] or return
      rest = rest.byteslice(http3.send_data(stream_id, rest, fin: true)..) || "".b
      rest.empty? ? @left.delete([http3, stream_id]) : @left[[http3, stream_id]] = rest
    end

    private def forget_closed
      super
      closed = @http3.select { |connection, _| connection.closed? }.map { |_, (http3, _)| http3 }
      @http3.delete_if { |connection, _| connection.closed? }
      @left.delete_if { |(http3, _), _| closed.include?(http3) }
    end
  end
end
