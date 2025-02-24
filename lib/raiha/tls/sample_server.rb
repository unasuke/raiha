require "socket"
require "logger"
require_relative "server"

module Raiha
  module TLS
    class SampleServer
      def self.start
        server = self.new
        begin
          server.connect!
        ensure
          server.close
        end
      end

      def initialize
        @server = Raiha::TLS::Server.new
        @host = "localhost"
        @port = 4433
        @socket = TCPServer.new(@host, @port)
        @logger = Logger.new($stdout)
      end

      def connect!
        @logger.info("Server started on #{@host}:#{@port}")
        server = @socket.accept
        loop do
          begin
            response = server.recvmsg_nonblock
            pp response.first if response
            @server.receive(response.first) if response

            @server.datagrams_to_send&.each do |datagram|
              server.sendmsg(datagram)
            end
          rescue IO::WaitReadable
            next
          end
        end
      end

      def close
        @socket&.close
      end
    end
  end
end
