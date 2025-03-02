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
          server.send("\n\n=====ping from server=====\n\n")
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
        @connection = nil
      end

      def connect!
        @logger.info("Server started on #{@host}:#{@port}")
        server = @socket.accept
        @connection = server
        loop do
          break if @server.connected?

          begin
            response = server.recvmsg_nonblock
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

      def send(data)
        @connection.sendmsg(@server.encrypt_application_data(data))
      end
    end
  end
end
