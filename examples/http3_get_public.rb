# Sends an HTTP/3 GET request to a handful of well-known public HTTP/3
# endpoints and prints the response status, content-type, and a short
# body excerpt to stdout. With no arguments, hits a built-in list; pass
# one or more URLs as ARGV to override.
#
# Usage:
#   bundle exec ruby -Ilib examples/http3_get_public.rb
#   bundle exec ruby -Ilib examples/http3_get_public.rb https://cloudflare-quic.com/
#
# Expected output (one block per target):
#   https://cloudflare-quic.com/
#     headers:
#       :status: 200
#       content-type: text/html
#       ... (all response headers, including the :status pseudo-header)
#     body (... bytes, first 80): "..."
#
# Caveats:
#   - raiha does NOT validate the server's certificate chain against a
#     trust store. lib/raiha/tls/client.rb only verifies the
#     CertificateVerify signature, so any cert the server presents is
#     accepted. Treat this script as a protocol demo, not as an
#     authenticated client.
#   - The hostname is resolved to an IPv4 address once via
#     Addrinfo.getaddrinfo and pinned for every datagram. Letting
#     UDPSocket#send re-resolve on each call lets glibc rotate across the
#     A records of multi-homed hosts (e.g. cloudflare-quic.com), which
#     splits packets across frontends that don't share QUIC connection
#     state and stalls the connection mid-flight.
#   - The default target list exercises three public HTTP/3 servers
#     (Cloudflare, NGINX, nghttpx). They each return 200 OK reliably
#     against raiha's current QUIC / HTTP/3 implementation. Failures
#     print "error: ..." and the script continues with the next target.

require "raiha/connection"
require "raiha/http3"
require "fileutils"
require "socket"
require "timeout"
require "uri"

DEFAULT_TARGETS = [
  "https://cloudflare-quic.com/",
  "https://quic.nginx.org/",
  "https://nghttp2.org/",
].freeze

HANDSHAKE_TIMEOUT = 10
RESPONSE_TIMEOUT = 10

# Resolve once and pin the IP for every send. UDPSocket#send(hostname)
# re-runs getaddrinfo on each call, and glibc rotates among the A records
# of multi-homed hosts like cloudflare-quic.com (104.18.26.14 vs
# 104.18.27.14). That sprays datagrams across different frontend servers
# that don't share QUIC connection state, so the handshake completes
# against one IP and the follow-up packets get black-holed by another.
def resolve_ip(host)
  Addrinfo.getaddrinfo(host, nil, :INET, :DGRAM).first&.ip_address or
    raise "No IPv4 address for #{host}"
end

def flush(connection, socket, ip, port)
  connection.get_packets_to_send.each { |pkt| socket.send(pkt, 0, ip, port) }
end

def drain(socket, connection, timeout: 0.3)
  loop do
    readable = IO.select([socket], nil, nil, timeout)
    break unless readable

    data, = socket.recvfrom_nonblock(65535)
    connection.handle_packet(data)
  rescue IO::WaitReadable
    break
  end
end

def fetch(url)
  uri = URI.parse(url)
  host = uri.host or raise ArgumentError, "URL has no host: #{url}"
  port = uri.port || 443
  path = uri.path.empty? ? "/" : uri.path
  path = "#{path}?#{uri.query}" if uri.query
  authority = port == 443 ? host : "#{host}:#{port}"
  ip = resolve_ip(host)
  qlog_path = "tmp/raiha-http3-public-#{Time.now.to_i}-#{host}.qlog"

  socket = UDPSocket.new
  socket.bind("0.0.0.0", 0)

  connection = Raiha::Connection.new(
    perspective: :client,
    src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
    dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
    alpn_protocols: ["h3"],
    server_name: host
  )
  connection.enable_qlog(output: qlog_path, title: "raiha #{url}")
  http3 = Raiha::HTTP3::Client.new(connection: connection)

  begin
    Timeout.timeout(HANDSHAKE_TIMEOUT) do
      connection.start_handshake
      until connection.handshake_complete?
        flush(connection, socket, ip, port)
        drain(socket, connection)
      end
    end

    http3.setup_control_stream
    request_stream = http3.send_request(
      method: "GET",
      scheme: "https",
      authority: authority,
      path: path,
      headers: [["user-agent", "raiha-example/0.0"]]
    )

    Timeout.timeout(RESPONSE_TIMEOUT) do
      loop do
        flush(connection, socket, ip, port)
        drain(socket, connection, timeout: 0.5)

        client_stream = connection.streams.get_stream(request_stream.stream_id.value)
        next unless client_stream&.fin_received?

        return http3.receive_response(client_stream)
      end
    end
  ensure
    if connection.handshake_complete?
      connection.close
      flush(connection, socket, ip, port)
    end
    connection.flush_qlog
    puts "qlog written: #{qlog_path}"
    socket.close
  end
end

def print_result(url, response)
  body_excerpt = response.body.byteslice(0, 80).to_s.gsub(/[\r\n]+/, " ").strip

  puts url
  puts "  headers:"
  response.headers.each { |name, value| puts "    #{name}: #{value}" }
  puts "  body (#{response.body.bytesize} bytes, first 80): #{body_excerpt.inspect}"
end

def print_error(url, error)
  puts url
  puts "  error: #{error.class}: #{error.message}"
end

targets = ARGV.empty? ? DEFAULT_TARGETS : ARGV

FileUtils.mkdir_p("tmp")

targets.each do |url|
  begin
    response = fetch(url)
    print_result(url, response)
  rescue StandardError => e
    print_error(url, e)
  end
  puts
end
