require 'socket'

socket = UDPSocket.new
socket.bind("0.0.0.0", 8080)

loop do
  begin
    raw_packet, addr = socket.recvmsg_nonblock(500)
  rescue IO::WaitReadable
    retry
  end
  if raw_packet
    socket.send(raw_packet, 0, addr)
  end
end
