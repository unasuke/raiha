require "socket"
require_relative "client"

module Raiha
  module TLS
    class SampleClient
      def self.start
        client = self.new
        begin
          client.connect!
          client.send("ping")
        ensure
          client.close
        end
      end

      def initialize
        @client = Raiha::TLS::Client.new
        @host = "localhost"
        @port = 4433
        @socket = TCPSocket.new(@host, @port)
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

      def close
        @socket&.close
      end

      def send(data)
        @socket.sendmsg(@client.encrypt_application_data(data))
      end
    end
  end
end
