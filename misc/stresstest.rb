require 'socket'
require 'openssl'

class Server
  def initialize
    @socket = UDPSocket.new
    @router = Router.new.ractor
  end

  def run
    @socket.bind("0.0.0.0", 8080)

    # receiver = Ractor.new do
    #   loop do
    #     puts Ractor.receive
    #   end
    # end

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
    # pp "aaa"
    # pp "bbb"
    sleep
  rescue Interrupt
    puts "Stop server"
    exit
  end
end

class Router
  def initialize
    @counter = 0
    @ractor = Ractor.new(@counter, []) do |counter, conns|
      loop do
        packet, addr, socket = Ractor.receive
        # puts addr.class
        # puts socket
        begin
          # if conns.size < 20
          #   conn = Connection.new
          #   conns << conn
          # end
          # conns.sample.ractor.send([packet, addr, socket])

          conn = Connection.new
          conn.ractor.send([packet, addr, socket])
        rescue => e
          puts e.inspect
          puts Process.getrlimit(:NOFILE)
          puts conns.count
          exit!
        end
      end
    end
  end

  def ractor
    @ractor
  end

  def count
    @counter
  end
end

class Connection
  # require 'securerandom'
  # require 'timeout'
  # require 'prime'
  require 'pp'

  def initialize
    @socket = UDPSocket.new
    # @packet = QuicInitialPacket.read(packet)
    @ractor = Ractor.new(@socket) do |socket|
      # loop do
        packet, addr, socket_a = Ractor.receive
        # puts packet
        # puts socket_a.inspect
        # puts Addrinfo.new(addr).inspect
        # sleep(0.5)
        # 10000.times.each {|n| n*n }
        pp "a"
        enc = OpenSSL::Cipher.new('aes-128-ecb')
        enc.encrypt

        enc.key = ["9f50449e04a0e810283a1e9933adedd2"].pack("H*") # hp

        mask = ""
        mask << enc.update("aaaa")
        mask << enc.final
        socket_a.send(packet, 0, addr)
        # puts packet
      end
      # begin
      #   Timeout.timeout(15) do
      #     loop do
      #       puts "connection"
      #       3.times { socket.send 'msg' }
      #     end
      #   end
      #   rescue Timeout::Error
      #     return
      # end
    # end
  end

  def ractor
    @ractor
  end
end

server = Server.new
server.run
