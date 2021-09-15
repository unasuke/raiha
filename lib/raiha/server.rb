require 'socket'
require 'raiha/packet/base'

module Raiha
  class Server
    def initialize
      @socket = UDPSocket.new
      @router = Router.new.ractor
    end

    def run
      @socket.bind("0.0.0.0", 8080)

      Ractor.new(@socket, @router) do |socket, router|
        loop do
          begin
            raw_packet, addr = socket.recvmsg_nonblock(2000)
          rescue IO::WaitReadable
            retry
          end
          router.send [raw_packet, addr.to_sockaddr, socket] if raw_packet
        end
      end
    
      puts "Start server"
      sleep
    rescue Interrupt
      puts "Stop server"
      exit
    end
  end

  class Router
    def initialize
      @counter = 0
      @ractor = Ractor.new(@counter) do |counter|
        loop do
          packet, addr, socket = Ractor.receive
          Connection.new.ractor.send([packet, addr, socket])
        end
      end
    end

    def ractor
      @ractor
    end
  end

  class Connection
    def initialize()
      @ractor = Ractor.new do
        packet, addr, socket = Ractor.receive
        # pp QuicInitialPacket.read(packet)
        protected_init = Raiha::Packet::Initial.new(packet)
        protected_init.parse
        init = protected_init.remove_protection
        puts init.parsed
      end
    end

    def ractor
      @ractor
    end
  end
end

if $0 == __FILE__
  server = Raiha::Server.new
  server.run
end
