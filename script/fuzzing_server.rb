#!/usr/bin/env ruby
# frozen_string_literal: true

# Fuzzing server for tlsfuzzer
# Usage: ruby -Ilib script/fuzzing_server.rb [port] [cert_file] [key_file]

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "socket"
require "raiha"
require "raiha/tls/client"
require "raiha/tls/server"
require "raiha/tls/config"
require "openssl"

port = (ARGV[0] || 4433).to_i
cert_path = ARGV[1]
key_path = ARGV[2]

config = Raiha::TLS::Config.server_default

if cert_path && key_path
  config.server_certificate = OpenSSL::X509::Certificate.new(File.read(cert_path))
  config.server_private_key = OpenSSL::PKey.read(File.read(key_path))
else
  # Generate self-signed certificate
  key = OpenSSL::PKey::RSA.generate(2048)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = 1
  cert.subject = OpenSSL::X509::Name.new([["CN", "localhost"]])
  cert.issuer = cert.subject
  cert.public_key = key.public_key
  cert.not_before = Time.now - 3600
  cert.not_after = Time.now + 86400

  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate = cert
  cert.add_extension(ef.create_extension("subjectAltName", "DNS:localhost"))
  cert.sign(key, "SHA256")

  config.server_certificate = cert
  config.server_private_key = key
end

HTTP_RESPONSE = <<~RESPONSE.gsub("\n", "\r\n")
  HTTP/1.0 200 OK
  Content-Type: text/plain
  Connection: close
  Content-Length: 2

  OK
RESPONSE

tcp_server = TCPServer.new("0.0.0.0", port)
$stderr.puts "Fuzzing server started on port #{port}"

loop do
  conn = tcp_server.accept
  Thread.new(conn) do |socket|
    socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    server = Raiha::TLS::Server.new(config: config)

    begin
      until server.connected?
        datagrams = server.datagrams_to_send
        if datagrams && !datagrams.empty?
          datagrams.flatten.each { |d| socket.write(d) }
          socket.flush
        end

        if IO.select([socket], nil, nil, 10)
          data = socket.recv(16384)
          break if data.nil? || data.empty?
          server.receive(data)
        else
          $stderr.puts "  Timeout waiting for data (state=#{server.state})"
          break
        end
      end

      if server.connected?
        # Read application data (HTTP request)
        if IO.select([socket], nil, nil, 5)
          data = socket.recv(16384)
          server.receive(data) if data && !data.empty?
        end

        # Send HTTP response
        encrypted = server.encrypt_application_data(HTTP_RESPONSE)
        socket.write(encrypted)
        socket.flush
      end
    rescue => e
      $stderr.puts "  Connection error: #{e.class}: #{e.message}"
      $stderr.puts "  #{e.backtrace.first(3).join("\n  ")}"
    ensure
      socket.close rescue nil
    end
  end
end
