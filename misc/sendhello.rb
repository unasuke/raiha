require "socket"

udp = UDPSocket.open()

sockaddr = Socket.pack_sockaddr_in(8080, "127.0.0.1")

pp udp.send("HELLO", 0, sockaddr)

udp.close