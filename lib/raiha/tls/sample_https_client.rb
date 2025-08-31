require "socket"
require_relative "client"

module Raiha
  module TLS
    class SampleHttpsClient
      def self.start(host: "localhost.unasuke.dev", port: 4433)
        client = self.new(host: host, port: port)
        begin
          client.connect!
          client.send(<<~HTTPGET)
            GET / HTTP/1.1\r
            Host: #{host}\r
            Connection: close\r

          HTTPGET
          puts client.read
        ensure
          client.close
        end
      end

      def initialize(host:, port:)
        @host = host
        @port = port
        @socket = TCPSocket.new(@host, @port)
        @client = Raiha::TLS::Client.new(server_name: @host)
      end

      def connect!
        loop do
          break if @client.finished?

          begin
            @client.datagrams_to_send&.each do |datagram|
              @socket.sendmsg(datagram)
            end
            response = @socket.recvmsg_nonblock
            @client.receive(response.first)
          rescue IO::WaitReadable
            next
          end
        end
      end

      def read
        buf = ""
        loop do
          response = @socket.recvmsg_nonblock
          break if !response || response.first.nil?

          buf += @client.receive(response.first)
        rescue IO::WaitReadable
          next
        end
        buf
      end

      def close
        @socket&.close
      end

      def send(data)
        @socket.sendmsg(@client.encrypt_application_data(data))
      end
    end
  end
end
