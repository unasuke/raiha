# frozen_string_literal: true

require "socket"

module Raiha::Next::Runtime
  # A UDP socket that carries QUIC: each datagram of a Transmit goes out
  # with its own `sendmsg`, marked with its ECN codepoint, and each datagram
  # that comes in is read with `recvmsg` along with the codepoint it was
  # marked with. Bound to "::", one socket takes IPv4 as well, and the peers
  # of IPv4 have IPv4-mapped addresses ("::ffff:192.0.2.1").
  class UDP
    # The most datagrams taken from the socket at once.
    RECEIVE_BATCH = 64
    # The largest datagram UDP carries.
    MAX_DATAGRAM = 65_535
    # The Linux default for the buffers (about 212 KB) is too small for a
    # burst: the kernel drops what overflows before it is read.
    BUFFER = 8 * 1024 * 1024
    # The low two bits of the traffic class, the ECN field (RFC 3168).
    ECN = { 0b00 => :not_ect, 0b01 => :ect1, 0b10 => :ect0, 0b11 => :ce }.freeze
    MARKS = { ect0: 0b10, ect1: 0b01 }.freeze
    # A peer gone or a datagram too big for the path is no reason to stop.
    DROPPED = [Errno::ECONNREFUSED, Errno::EMSGSIZE, Errno::ENETUNREACH, Errno::EHOSTUNREACH, Errno::EADDRNOTAVAIL].freeze

    # A socket bound to `host` and `port` (0 for one the OS chooses).
    def self.bind(host, port)
      family = Addrinfo.udp(host, port).afamily
      socket = UDPSocket.new(family)
      socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, 0) if family == Socket::AF_INET6
      socket.bind(host, port)
      new(socket)
    end

    def initialize(socket)
      @socket = socket
      @family = socket.local_address.afamily
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, BUFFER)
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, BUFFER)
      # An IPv6 socket that takes IPv4 tells the codepoint of an IPv4
      # datagram the IPv4 way.
      @socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_RECVTOS, 1)
      @socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_RECVTCLASS, 1) if @family == Socket::AF_INET6
    end

    # [address, port] the socket is bound to.
    def local_address
      address = @socket.local_address
      [address.ip_address, address.ip_port]
    end

    # Sends each datagram of `transmit`; whether all of them went. The ECN
    # mark of an IPv4 destination, IPv4-mapped included, goes as IP_TOS:
    # Linux leaves IPV6_TCLASS off a datagram that leaves as IPv4.
    def send(transmit)
      host, port = transmit.destination
      destination = Socket.sockaddr_in(port, host)
      mark = mark(transmit.ecn, host)
      datagrams(transmit).all? do |datagram|
        mark ? @socket.sendmsg(datagram, 0, destination, mark) : @socket.sendmsg(datagram, 0, destination)
        true
      rescue *DROPPED
        false
      end
    end

    # The datagrams there now, RECEIVE_BATCH at most, each as [data,
    # [address, port], ecn]; none when there are none.
    def receive
      received = [] #: Array[[String, address, ecn]]
      while received.size < RECEIVE_BATCH
        result = @socket.recvmsg_nonblock(MAX_DATAGRAM, 0, exception: false)
        break unless result.is_a?(Array)
        data, from = result
        # The control messages follow the flags one by one, not as an Array
        # as the bundled declaration has it.
        controls = result.drop(3) #: Array[Socket::AncillaryData]
        received << [data, [from.ip_address, from.ip_port], ecn(controls)]
      end
      received
    rescue *DROPPED
      received || []
    end

    # Waits until a datagram is there or `timeout` seconds have gone
    # (forever when nil); whether one is there. Under a Fiber scheduler only
    # the fiber waits.
    def wait_readable(timeout = nil) = @socket.wait_readable(timeout) ? true : false

    def close = @socket.close

    def closed? = @socket.closed?

    private def datagrams(transmit)
      payload = transmit.payload
      size = transmit.segment_size
      return [payload] unless size && size < payload.bytesize
      (0...payload.bytesize).step(size).map { |offset| payload.byteslice(offset, size) || "".b }
    end

    private def mark(ecn, host)
      value = MARKS[ecn] or return nil
      if @family == Socket::AF_INET6 && !(host.start_with?("::ffff:") && host.include?("."))
        Socket::AncillaryData.int(:INET6, :IPV6, :TCLASS, value)
      else
        Socket::AncillaryData.int(:INET, :IP, :TOS, value)
      end
    end

    # The codepoint of a datagram from its control messages: IP_TOS is one
    # byte, IPV6_TCLASS an int.
    private def ecn(controls)
      controls.each do |control|
        return ECN.fetch(control.data.getbyte(0).to_i & 0b11) if control.cmsg_is?(Socket::IPPROTO_IP, Socket::IP_TOS)
        return ECN.fetch(control.int & 0b11) if control.cmsg_is?(Socket::IPPROTO_IPV6, Socket::IPV6_TCLASS)
      end
      :not_ect
    end
  end
end
