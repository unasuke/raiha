require "raiha/next/support/quic_tls"
require "raiha/next/quic/test"
require "socket"
require "tmpdir"

# A client Connection or a server's Endpoint of the next release of raiha
# on a UDP socket of the loopback interface, run with the loop an
# application writes, against another implementation of QUIC run as a
# process of its own.
module NextQUICUDP
  include NextQUICTLS

  TMP = File.expand_path("../../../../tmp", __dir__)
  TICK = 0.05

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
  # of its own, for the block. The connection closes after.
  def client(port, alpn:)
    tls_config = NextTLSPair.client_config(profile: TLS::Profile::QUIC, alpn:, registry: REGISTRY)
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    connection = QUIC::Connection.client(config: QUIC::Config.new, tls_config:, keyring: TLS::Keyring.client(config: tls_config),
      server_name: "localhost", remote: ["127.0.0.1", port], time: Time.now, now: mono)
    yield socket, connection
  ensure
    if connection
      connection.close(now: mono)
      connection.each_transmit(now: mono) { |t| socket.send(t.payload, 0, *t.destination) }
    end
    socket&.close
  end

  # A server's Endpoint that takes every client with `alpn`, on a socket of
  # its own at a free port, for the block, as a QUIC::Test::Server.
  def server(alpn:)
    tls_config = NextTLSPair.server_config(profile: TLS::Profile::QUIC, alpn:, registry: REGISTRY)
    keyring = TLS::Keyring.server(config: tls_config, identities: [NextTLSPair.server_identity])
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    endpoint = QUIC::Endpoint.server(config: QUIC::Config.new, random: SecureRandom, time: Time.now, now: mono)
    yield socket, QUIC::Test::Server.new(endpoint, tls_config:, keyring:)
  ensure
    socket&.close
  end
end
