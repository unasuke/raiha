#!/usr/bin/env ruby
# frozen_string_literal: true

# A TLS 1.3 server over TCP of the next release of raiha (TLS::TCP::Socket)
# for tlsfuzzer: it takes connections on `port` and completes each
# handshake; then it answers an HTTP GET with a short response, and other
# data, each line as it ends, with the same bytes back, as tlsfuzzer's
# scripts expect of an echo server; it reads until the client closes, and
# closes with close_notify. What fails in one connection is printed and the
# server goes on. Its certificate is a self-signed RSA one made on start,
# unless `cert_file` and `key_file` (PEM) are given.
#
# Usage:
#   bundle exec ruby script/fuzzing_server.rb [port] [cert_file] [key_file]   (4433 by default)

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "socket"
require "openssl"
require "raiha/next/tls"

TLS = Raiha::Next::TLS
# Connections handled at once, each in a thread of its own.
THREADS = 4

port = (ARGV[0] || 4433).to_i
cert_path = ARGV[1]
key_path = ARGV[2]

if cert_path && key_path
  cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
  key = OpenSSL::PKey.read(File.read(key_path))
else
  key = OpenSSL::PKey::RSA.generate(2048)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = 1
  cert.subject = OpenSSL::X509::Name.new([["CN", "localhost"]])
  cert.issuer = cert.subject
  cert.public_key = key.public_key
  cert.not_before = Time.now - 3600
  cert.not_after = Time.now + 86_400
  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = cert
  factory.issuer_certificate = cert
  cert.add_extension(factory.create_extension("subjectAltName", "DNS:localhost"))
  cert.sign(key, "SHA256")
end

config = TLS::Config.server
keyring = TLS::Keyring.server(config:, identities: [TLS::Keyring::Identity.new(cert_der: [cert.to_der], key_der: key.private_to_der)])

HTTP_RESPONSE = <<~RESPONSE.gsub("\n", "\r\n")
  HTTP/1.0 200 OK
  Content-Type: text/plain
  Connection: close
  Content-Length: 2

  OK
RESPONSE

listener = TCPServer.new("0.0.0.0", port)
$stderr.puts "Fuzzing server started on port #{port}"

Array.new(THREADS) do
  Thread.new do
    loop do
      TLS::TCP::Socket.accept(listener, config:, keyring:) do |socket|
        pending = "".b
        while (data = socket.read(16_384))
          pending << data
          if pending.start_with?("GET ")
            next unless pending.include?("\r\n\r\n")
            socket.write(HTTP_RESPONSE)
            pending = "".b
          elsif pending.end_with?("\n")
            socket.write(pending)
            pending = "".b
          end
        end
      end
    rescue StandardError => e
      $stderr.puts "  Connection error: #{e.class}: #{e.message}"
    end
  end
end.each(&:join)
