# frozen_string_literal: true

require_relative "next_quic"

module RaihaInterop
  # The server of hq-interop on the next release of raiha: an Endpoint on
  # UDP port 443 that takes every client, after a Retry for the retry
  # testcase, and answers each request, "GET /path\r\n" on a stream the
  # client opens, with the file of the path under WWW, ending the stream.
  # A path with no file gets nothing. It runs until the runner stops it.
  #
  # It gives tickets sealed with a key made at random as it starts, and
  # takes 0-RTT from them. As no ticket opens from before the start, the
  # record of 0-RTT taken needs no time to warm up.
  class NextServer
    include NextQUIC

    PORT = 443
    # How much of a response goes to stream_write at a time.
    PIECE = 65_536

    # What is left to write of a response.
    Response = Struct.new(:data, :offset)

    def initialize(env:, testcase:, logger:)
      @env = env
      @testcase = testcase
      @logger = logger
      # Requests and responses by [connection, stream ID].
      @requests = {}
      @responses = {}
    end

    def run
      @tls_config = TLS::Config.server(profile: TLS::Profile::QUIC, alpn:, registry: REGISTRY, ticket_key: SecureRandom.bytes(32),
        max_early_data_size: 0xffff_ffff)
      @keyring = TLS::Keyring.server(config: @tls_config, identities: [identity])
      @anti_replay = TLS::AntiReplay::Memory.new(now: Time.now, warmup: false)
      @keylog = keylog
      socket = udp_socket
      socket.bind("0.0.0.0", (@env["BIND_PORT"] || PORT).to_i)
      endpoint = QUIC::Endpoint.server(config: quic_config, random: SecureRandom, time: Time.now, now: mono)
      log("listening on port #{socket.addr[1]} testcase=#{@testcase}")
      loop do
        endpoint.each_transmit(now: mono) { |transmit| send_transmit(socket, transmit) }
        receive_datagrams(socket, endpoint.next_timeout).each do |data, from|
          dispatch(endpoint, socket, endpoint.receive(data, from:, now: mono))
        end
        deadline = endpoint.next_timeout
        endpoint.handle_timeout(now: mono) if deadline && deadline <= mono
        endpoint.each_connection { |connection| serve(connection) }
        forget_closed
      end
    rescue StandardError => error
      log("server error: #{error.class}: #{error.message}")
      log(error.backtrace.first(8).join("\n")) if error.backtrace
      1
    end

    # What the application does with a Route: a Retry first for the retry
    # testcase, then the ClientHello read and accepted.
    private def dispatch(endpoint, socket, route)
      case route
      when QUIC::Route::Incoming
        return endpoint.retry(route.handle, now: mono) if @testcase == "retry" && !route.address_validated
        dispatch(endpoint, socket, endpoint.admit(route.handle, now: mono))
      when QUIC::Route::ClientHello
        endpoint.accept(route.handle, tls_config: @tls_config, keyring: @keyring, now: mono, tracer: qlog(:server), keylog: @keylog,
          anti_replay: @anti_replay)
      when QUIC::Route::Respond then send_transmit(socket, route.transmit)
      end
    end

    private def serve(connection)
      connection.each_event { |event| log("closed: #{event.error.inspect}") if event.is_a?(QUIC::Event::Closed) }
      return unless connection.handshake_complete?
      return if connection.closing? || connection.draining? || connection.closed?
      connection.readable_streams.to_a.each { |stream_id| take_request(connection, stream_id) }
      @responses.each { |(owner, stream_id), response| respond(connection, stream_id, response) if owner.equal?(connection) }
      @responses.delete_if { |_, response| response.offset.nil? }
    end

    # Reads the request on `stream_id`, and once it has ended, finds its
    # response.
    private def take_request(connection, stream_id)
      key = [connection, stream_id]
      request = (@requests[key] ||= "".b)
      while (chunk = connection.stream_read(stream_id, PIECE))
        return if chunk.empty?
        request << chunk
      end
      @requests.delete(key)
      @responses[key] = Response.new(file(request[/\AGET (\S+)/, 1]), 0)
    end

    # Writes what the stream takes of `response`, ending the stream with
    # its last byte; the offset is nil once all of it is written.
    private def respond(connection, stream_id, response)
      data = response.data
      loop do
        piece = data.byteslice(response.offset, PIECE) || "".b
        last = response.offset + piece.bytesize == data.bytesize
        taken = connection.stream_write(stream_id, piece, fin: last)
        response.offset += taken
        return response.offset = nil if last && taken == piece.bytesize
        return if taken < piece.bytesize
      end
    rescue QUIC::Error::StreamError => error
      log("stream #{stream_id}: #{error.message}")
      response.offset = nil
    end

    # The file of `path` under WWW; nothing for a path that leads out of it
    # or to no file.
    private def file(path)
      root = File.expand_path(@env["WWW"] || "/www")
      full = File.expand_path(File.join(root, path.to_s))
      return "".b unless full.start_with?("#{root}/") && File.file?(full)
      File.binread(full)
    end

    private def forget_closed
      @requests.delete_if { |(connection, _), _| connection.closed? }
      @responses.delete_if { |(connection, _), _| connection.closed? }
    end

    # The certificate chain and key in CERTS.
    private def identity
      TLS::Keyring::Identity.new(cert_der: certificates_der(File.join(certs_dir, "cert.pem")),
        key_der: OpenSSL::PKey.read(File.read(File.join(certs_dir, "priv.key"))).private_to_der)
    end

    private def log(message) = @logger.puts("[raiha-interop next server] #{message}")
  end
end
