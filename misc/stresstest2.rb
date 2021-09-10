require 'socket'
require 'openssl'

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
        # pp Ractor.main
        # puts addr.ip_address if raw_packet
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
    @ractor = Ractor.new() do
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
  def initialize
    @ractor = Ractor.new() do
        packet, addr, socket = Ractor.receive
        socket.send(packet, 0, addr)
      end
  end

  def ractor
    @ractor
  end
end

server = Server.new
server.run
