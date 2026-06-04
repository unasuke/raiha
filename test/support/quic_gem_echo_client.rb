# frozen_string_literal: true

# Interop echo client driven by the quic gem (github: unasuke/quic-ruby), a
# thin ngtcp2 + LibreSSL binding. Counterpart to test/support/aioquic_client.py.
#
# Connects to a raiha QUIC server over loopback UDP, completes the handshake,
# and (when --data is given) opens a client-initiated bidirectional stream,
# writes the payload with FIN, then blocks until the server echoes the bytes
# back. The driving test asserts on both this script's stdout markers and its
# exit code.
#
# Output contract (consumed by RaihaQuicGemInteropTest):
#   - success:        stdout "HANDSHAKE_COMPLETE" (+ "ECHO_OK" in echo mode), exit 0
#   - echo mismatch:  stderr "ECHO_MISMATCH ..." , exit 1
#   - any exception:  stderr backtrace            , exit 1
#
# Usage:
#   bundle exec ruby test/support/quic_gem_echo_client.rb \
#     --host 127.0.0.1 --port 4433 --alpn raiha-interop [--data <hex>]

require "optparse"
require "socket"
require "quic"

options = {}
OptionParser.new do |opts|
  opts.on("--host HOST") { |v| options[:host] = v }
  opts.on("--port PORT", Integer) { |v| options[:port] = v }
  opts.on("--alpn ALPN") { |v| options[:alpn] = v }
  opts.on("--data HEX") { |v| options[:data] = v }
end.parse!

%i[host port alpn].each do |key|
  raise ArgumentError, "missing required --#{key}" unless options[key]
end

begin
  sock = UDPSocket.new
  sock.connect(options[:host], options[:port])

  settings = Quic::Settings.default.with(alpn: [options[:alpn]])
  client = Quic::Connection::Client.new(
    host: options[:host],
    port: options[:port],
    settings: settings
  )
  client.bind(sock).run

  puts "HANDSHAKE_COMPLETE"
  $stdout.flush

  if options[:data]
    payload = [options[:data]].pack("H*")
    stream = client.open_bidi_stream
    stream.write(payload, fin: true)
    echo = stream.read

    expected = "ECHO:".b + payload
    if echo == expected
      puts "ECHO_OK"
      $stdout.flush
    else
      warn "ECHO_MISMATCH expected=#{expected.unpack1("H*")} got=#{echo&.unpack1("H*")}"
      exit 1
    end
  end
rescue => e
  warn "#{e.class}: #{e.message}"
  warn e.backtrace.join("\n")
  exit 1
ensure
  sock&.close
end
