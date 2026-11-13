require "support/quic_tls"
require "fileutils"
require "raiha/quic/test"
require "socket"
require "tmpdir"

# A client Connection or a server's Endpoint of the next release of raiha
# on a UDP socket of the loopback interface, run with the loop an
# application writes, against another implementation of QUIC run as a
# process of its own.
module NextQUICUDP
  include NextQUICTLS

  # tmp/ is not in git, so a fresh checkout has none.
  TMP = File.expand_path("../../tmp", __dir__).tap { |dir| FileUtils.mkdir_p(dir) }
  TICK = 0.05

  # A client's application that, once the handshake is confirmed, or with
  # `early` while 0-RTT goes, sends `payload` on a stream of its own and
  # ends it, and reads what comes back to its end. It keeps the tickets the
  # server gives, and what the handshake came to.
  class EchoClient
    attr_reader :received, :tickets, :handshake

    def initialize(connection, payload, early: false)
      @connection = connection
      @payload = payload
      @early = early
      @written = 0
      @received = "".b
      @ended = false
      @tickets = []
      @handshake = nil
    end

    # A turn of the application: whether what came back has ended, or the
    # connection with it.
    def step
      @connection.each_event { |event| take(event) }
      return true if @ended || @connection.closing? || @connection.draining? || @connection.closed?
      return false unless @connection.handshake_confirmed? || (@early && @connection.zero_rtt_state == :pending)
      stream_id = (@stream_id ||= @connection.open_stream) or return false
      if @written < @payload.bytesize
        @written += @connection.stream_write(stream_id, @payload.byteslice(@written..) || "".b, fin: true)
      end
      while (chunk = @connection.stream_read(stream_id, 65_536))
        return false if chunk.empty?
        @received << chunk
      end
      @ended = true
    end

    private def take(event)
      case event
      when Raiha::Next::QUIC::Event::SessionTicket then @tickets << event.session
      when Raiha::Next::QUIC::Event::Connected then @handshake = event.handshake
      end
    end
  end

  # A server's application that answers each stream a client opens with
  # "ECHO:" and what came on it, once it has ended.
  class EchoServer
    def initialize(server)
      @server = server
      @streams = {}
    end

    # A turn of the application.
    def step
      @server.connections.each do |connection|
        connection.each_event { nil }
        next unless connection.handshake_complete? && !connection.closing? && !connection.draining? && !connection.closed?
        connection.readable_streams.to_a.each { |stream_id| take(connection, stream_id) }
        @streams.each do |(owner, stream_id), stream|
          next unless owner.equal?(connection) && stream[:reply] && !stream[:reply].empty?
          taken = connection.stream_write(stream_id, stream[:reply], fin: true)
          stream[:reply] = stream[:reply].byteslice(taken..) || "".b
        end
      end
    end

    private def take(connection, stream_id)
      stream = @streams[[connection, stream_id]] ||= { data: "".b, reply: nil }
      while (chunk = connection.stream_read(stream_id, 65_536))
        return if chunk.empty?
        stream[:data] << chunk
      end
      stream[:reply] = "ECHO:".b + stream[:data]
    end
  end

  module_function

  def mono = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  def free_port = UDPSocket.open { |socket| socket.bind("127.0.0.1", 0) && socket.addr[1] }

  # The files of a server certificate for "localhost" the test CA issues,
  # with the CA after it in the chain, and of its key: [chain, key].
  def certificate_files(dir)
    leaf = NextTestPKI.leaf(NextTLSPair.ca)
    chain = File.join(dir, "chain.pem").tap { File.write(_1, leaf.certificate.to_pem + NextTLSPair.ca.certificate.to_pem) }
    key = File.join(dir, "key.pem").tap { File.write(_1, leaf.key.private_to_pem) }
    [chain, key]
  end

  # Runs `command` for the block, which is given a String that grows with
  # what the process puts out. The process is ended after.
  def peer(*command)
    reader, writer = IO.pipe
    pid = Process.spawn(*command, in: File::NULL, out: writer, err: writer)
    writer.close
    output = +""
    thread = Thread.new { reader.each_line { output << _1 } }
    yield output
  ensure
    if pid
      Process.kill(:TERM, pid) rescue nil # rubocop:disable Style/RescueModifier
      Process.wait(pid)
    end
    thread&.join(1)
    reader&.close
  end

  # Waits until `output` has `line`, for at most `seconds`.
  def wait_for(output, line, seconds: 60)
    limit = mono + seconds
    sleep 0.01 until output.include?(line) || mono > limit
    output.include?(line)
  end

  # Runs `peer`, a Connection or a QUIC::Test::Server, on `socket` until
  # the block is true or `seconds` have gone by: whether the block came
  # true. The block may wait on what the other process puts out, so the
  # loop looks again every TICK seconds; a timeout handled before it is
  # due does nothing.
  def drive(socket, peer, seconds: 10)
    limit = mono + seconds
    until yield
      return false if mono > limit
      peer.each_transmit(now: mono) { |t| socket.send(t.payload, 0, *t.destination) }
      deadline = [peer.next_timeout, limit, mono + TICK].compact.min
      if IO.select([socket], nil, nil, [deadline - mono, 0].max)
        data, addr = socket.recvfrom(65535)
        peer.receive(data, from: [addr[3], addr[1]], to: nil, ecn: :not_ect, now: mono)
      else
        peer.handle_timeout(now: mono)
      end
    end
    true
  end

  # A client connection with `alpn` to the server at `port`, on a socket
  # of its own, for the block, with `options` of Connection.client
  # (session:, early_data:). The connection closes after.
  def client(port, alpn:, **options)
    tls_config = NextTLSPair.client_config(profile: TLS::Profile::QUIC, alpn:, registry: REGISTRY)
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    connection = QUIC::Connection.client(config: QUIC::Config.new, tls_config:, keyring: TLS::Keyring.client(config: tls_config),
      server_name: "localhost", remote: ["127.0.0.1", port], time: Time.now, now: mono, **options)
    yield socket, connection
  ensure
    if connection
      connection.close(now: mono)
      connection.each_transmit(now: mono) { |t| socket.send(t.payload, 0, *t.destination) }
    end
    socket&.close
  end

  # A server's Endpoint that takes every client with `alpn`, on a socket of
  # its own at a free port, for the block, as a QUIC::Test::Server. With
  # `resumption`, it gives tickets of a key made at random and takes 0-RTT
  # from them, so its record needs no time to warm up.
  def server(alpn:, resumption: false)
    tickets = resumption ? { ticket_key: SecureRandom.bytes(32), max_early_data_size: 1 } : {}
    tls_config = NextTLSPair.server_config(profile: TLS::Profile::QUIC, alpn:, registry: REGISTRY, **tickets)
    keyring = TLS::Keyring.server(config: tls_config, identities: [NextTLSPair.server_identity])
    anti_replay = TLS::AntiReplay::Memory.new(now: Time.now, warmup: false) if resumption
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: SecureRandom, time: Time.now, now: mono)
    yield socket, QUIC::Test::Server.new(endpoint, tls_config:, keyring:, anti_replay:)
  ensure
    socket&.close
  end
end
