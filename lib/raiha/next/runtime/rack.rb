# frozen_string_literal: true

require_relative "../runtime"

module Raiha::Next::Runtime
  # Rack 3 over the server of HTTP/3 of the runtime:
  #
  #   server.run(&Raiha::Next::Runtime::Rack.new(app))
  #
  # Each request is made an env, its body read as it comes through
  # rack.input, and what the application returns is written as the
  # response: a body that answers `each` chunk by chunk, one that answers
  # `call` (a streaming body) with a stream that reads the request and
  # writes the response. A header value of an Array goes as a field line
  # of each. The trailer fields, the priority and the rest of the request
  # are in env["raiha.request"]. It depends on no rack gem.
  #
  # A header field whose name has an underscore is left out of the env, as
  # it would be taken for the one with a hyphen there (HTTP_X_FORWARDED_FOR
  # of x_forwarded_for), and HTTP_HOST, SERVER_NAME and SERVER_PORT come
  # once from :authority, or the host field when there is none. A request
  # of a scheme other than http and https is answered with 400.
  class Rack
    SCHEMES = %w[http https].freeze

    # rack.input: the body of the request as it comes, read as an IO is.
    class Input
      def initialize(body)
        @body = body
        @buffer = "".b
        @ended = false
      end

      # With `length`, up to that many bytes, nil at the end; without, all
      # that is left, "" at the end.
      def read(length = nil, outbuf = nil)
        fill until @ended || (length && @buffer.bytesize >= length)
        data = length ? @buffer.byteslice(0, length) || "".b : @buffer
        @buffer = @buffer.byteslice(data.bytesize..) || "".b
        return nil if length && length.positive? && data.empty?
        outbuf ? outbuf.replace(data) : data
      end

      # The next line, nil at the end.
      def gets
        fill until @ended || @buffer.include?("\n")
        return nil if @buffer.empty?
        line = @buffer.byteslice(0, (@buffer.index("\n") || (@buffer.bytesize - 1)) + 1) || "".b
        @buffer = @buffer.byteslice(line.bytesize..) || "".b
        line
      end

      def each
        while (line = gets)
          yield line
        end
      end

      def close = nil

      private def fill
        chunk = @body.read_chunk
        chunk ? @buffer << chunk : @ended = true
      end
    end

    # The stream a streaming body is called with: it reads the request and
    # writes the response.
    class Stream
      def initialize(input, output)
        @input = input
        @output = output
        @read_closed = false
        @write_closed = false
      end

      def read(...) = @input.read(...)

      def write(data) = @output.write(data)

      def <<(data)
        write(data)
        self
      end

      def flush = self

      def close_read
        @read_closed = true
        nil
      end

      def close_write
        @write_closed = true
        nil
      end

      def close
        close_read
        close_write
      end

      def closed? = @read_closed && @write_closed
    end

    # What the body of a response to HEAD is written to: nothing, as such a
    # response has no content (RFC 9110 "HEAD").
    class Discard
      def write(data) = data.bytesize

      def <<(_data) = self
    end

    def initialize(app)
      @app = app
    end

    def to_proc = method(:call).to_proc

    # Answers `request` with what the application gives for its env.
    def call(request)
      return request.respond(400) unless SCHEMES.include?(request.scheme)
      env = env(request)
      status, headers, body = @app.call(env)
      # A body of Rack answers `each` or `call`, which steep does not narrow
      # to by `respond_to?`.
      request.respond(status, fields(headers)) do |response|
        output = request.method == "HEAD" ? Discard.new : response
        if body.respond_to?(:each)
          body.each { |chunk| output << chunk } # steep:ignore
        else
          body.call(Stream.new(env.fetch("rack.input"), output)) # steep:ignore
        end
      end
    ensure
      body.close if body.respond_to?(:close) # steep:ignore
    end

    private def env(request)
      authority = request.authority || request.headers.find { |name, _| name == "host" }&.last || ""
      host, port = authority.match(/\A(\[[^\]]*\]|[^:]*)(?::(\d+))?\z/)&.captures
      path, query = request.path.split("?", 2)
      env = {
        "REQUEST_METHOD" => request.method, "SCRIPT_NAME" => "", "PATH_INFO" => path || "", "QUERY_STRING" => query || "",
        "SERVER_NAME" => host || "", "SERVER_PORT" => port || "443", "SERVER_PROTOCOL" => "HTTP/3", "HTTP_HOST" => authority,
        "rack.url_scheme" => request.scheme || "https", "rack.input" => Input.new(request.body), "rack.errors" => $stderr,
        "raiha.request" => request
      } #: Hash[String, String | Input | IO | HTTP3::Request | Array[String]]
      env["rack.protocol"] = [request.protocol] if request.protocol
      request.headers.each do |name, value|
        next if name == "host" || name.include?("_")
        key = { "content-type" => "CONTENT_TYPE", "content-length" => "CONTENT_LENGTH" }.fetch(name) { "HTTP_#{name.upcase.tr("-", "_")}" }
        # Cookie lines are joined with "; " (RFC 9114 "Header Compression"),
        # others with ", ".
        env[key] = env.key?(key) ? "#{env[key]}#{name == "cookie" ? "; " : ", "}#{value}" : value
      end
      env
    end

    # The field lines of the headers of a response.
    private def fields(headers)
      headers.flat_map do |name, value|
        next [] if name.start_with?("rack.")
        Array(value).map { |line| [name, line.to_s] }
      end
    end
  end
end
