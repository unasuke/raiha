# frozen_string_literal: true

require "socket"

module Raiha::Next::Runtime
  # A UDP socket that carries QUIC: the datagrams of a Transmit go out, on
  # Linux, in one `sendmsg` that the kernel cuts at the segment size (GSO,
  # UDP_SEGMENT), elsewhere each with its own, marked with its ECN
  # codepoint; each datagram that comes in is read with `recvmsg` along with
  # the codepoint it was marked with and the address it came to (IP_PKTINFO,
  # IPV6_PKTINFO), and one sent from an address of the Transmit's goes
  # from there by the same control message. Bound to "::", one socket takes IPv4
  # as well; the addresses of IPv4 it tells are IPv4's ("192.0.2.1", not
  # the IPv4-mapped "::ffff:192.0.2.1"), so that a peer is the same
  # address whichever socket it came on, and it maps them back to send.
  #
  # On Linux, IP fragments nothing it sends and the kernel's idea of the
  # path MTU is left aside (PMTUDISC_PROBE), so that a probe for a larger
  # datagram is lost or refused (EMSGSIZE) rather than pass in pieces;
  # elsewhere, the runtime sends no probe (UDP.pmtud).
  #
  # Where the kernel will not cut them, a path with no checksum offload
  # (EIO, as ns-3's simulator has it) or a kernel without UDP_SEGMENT
  # (ENOPROTOOPT), the datagrams go one by one and the socket no longer
  # tries; it gives up on EINVAL or EMSGSIZE too, unless one by one they
  # fail all the same, when the destination is at fault, not GSO.
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
    # A peer gone or a datagram too big for the path is no reason to stop,
    # nor an address the OS will not send to, as port 0 (EINVAL) or a
    # broadcast (EACCES): a peer that spoofs its source chooses where the
    # responses of an Endpoint go. A firewall that refuses (EPERM) or a
    # kernel short of buffers (ENOBUFS) loses one datagram.
    DROPPED = [Errno::ECONNREFUSED, Errno::EMSGSIZE, Errno::ENETUNREACH, Errno::EHOSTUNREACH, Errno::EADDRNOTAVAIL,
      Errno::EINVAL, Errno::EACCES, Errno::EPERM, Errno::ENOBUFS].freeze
    # Linux's UDP_SEGMENT, a control message at the level of UDP, which
    # Socket does not name.
    UDP_SEGMENT = 103
    # Linux's IP_PMTUDISC_PROBE and IPV6_PMTUDISC_PROBE, which Socket does
    # not name either.
    PMTUDISC_PROBE = 3
    # What GSO refuses with; the first two say it never works here.
    GSO_REFUSED = [Errno::EIO, Errno::ENOPROTOOPT, Errno::EINVAL, Errno::EMSGSIZE].freeze
    GSO_UNAVAILABLE = [Errno::EIO, Errno::ENOPROTOOPT].freeze
    # The most a Transmit carries for GSO: the largest UDP payload over
    # IPv4, a Config's max_transmit_size when the application leaves it.
    MAX_TRANSMIT = 65_507

    # `config` with MAX_TRANSMIT for max_transmit_size, unless it has one:
    # a socket here sends the datagrams of a Transmit as they are cut.
    def self.batching(config) = config.max_transmit_size ? config : config.with(max_transmit_size: MAX_TRANSMIT)

    # Whether a socket here keeps IP from fragmenting what it sends.
    def self.unfragmented? = RUBY_PLATFORM.include?("linux") && Socket.const_defined?(:IP_MTU_DISCOVER) &&
      Socket.const_defined?(:IPV6_MTU_DISCOVER)

    # `config` with enable_pmtud false where a socket cannot keep IP from
    # fragmenting, so that no probe passes in pieces.
    def self.pmtud(config) = unfragmented? || !config.enable_pmtud ? config : config.with(enable_pmtud: false)

    # A socket bound to `host` and `port` (0 for one the OS chooses); with
    # `reuse_port`, one of several that share the address (UDP.open).
    def self.bind(host, port, reuse_port: false) = new(open(host, port, reuse_port:))

    # A plain UDPSocket bound to `host` and `port`, as `bind` wraps, which
    # can be moved to another Ractor and wrapped there. With `reuse_port`
    # (SO_REUSEPORT, set before binding), other sockets with it may bind
    # the same address, and the kernel gives each the datagrams of some
    # 4-tuples, as the workers of a server take theirs.
    def self.open(host, port, reuse_port: false)
      family = Addrinfo.udp(host, port).afamily
      socket = UDPSocket.new(family)
      socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, 0) if family == Socket::AF_INET6
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, 1) if reuse_port
      socket.bind(host, port)
      socket
    rescue StandardError
      socket&.close
      raise
    end

    def initialize(socket)
      @socket = socket
      local = socket.local_address
      @family = local.afamily
      @port = local.ip_port
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, BUFFER)
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, BUFFER)
      # An IPv6 socket that takes IPv4 tells the codepoint of an IPv4
      # datagram the IPv4 way.
      @socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_RECVTOS, 1)
      @socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_RECVTCLASS, 1) if @family == Socket::AF_INET6
      # The address a datagram came to, at both levels on a socket that
      # takes both.
      @socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_PKTINFO, 1)
      @socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_RECVPKTINFO, 1) if @family == Socket::AF_INET6
      # No fragments, at both levels on a socket that sends both.
      if UDP.unfragmented?
        @socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MTU_DISCOVER, PMTUDISC_PROBE)
        @socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_MTU_DISCOVER, PMTUDISC_PROBE) if @family == Socket::AF_INET6
      end
      @gso = RUBY_PLATFORM.include?("linux")
    end

    # [address, port] the socket is bound to.
    def local_address
      address = @socket.local_address
      [address.ip_address, address.ip_port]
    end

    # Whether a datagram from `address` ([address, port]) goes from this
    # socket: the port is the socket's, and so is the address, or the
    # socket is bound to any of its family, IPv4 too for "::".
    def sends_from?(address)
      host, port = address
      return false unless port == @port
      bound = @socket.local_address
      return true if bound.ipv6? && bound.ipv6_unspecified?
      return !host.include?(":") if bound.ip_address == "0.0.0.0"
      unmapped(bound.ip_address) == host
    end

    # Sends each datagram of `transmit`; whether all of them went. The ECN
    # mark of an IPv4 destination, IPv4-mapped included, goes as IP_TOS:
    # Linux leaves IPV6_TCLASS off a datagram that leaves as IPv4. The
    # Transmit's source, when it has one, is the address the datagrams go
    # from; the port is the socket's. When GSO
    # fails, the datagrams go one by one, each lost alone; GSO goes for
    # good when it is unavailable here, or when it refused what went one by
    # one, so that the fault was not the destination's.
    def send(transmit)
      host, port = transmit.destination
      host = mapped(host)
      destination = Socket.sockaddr_in(port, host)
      controls = [mark(transmit.ecn, host), source(transmit.source)].compact
      size = transmit.segment_size
      if @gso && size && size < transmit.payload.bytesize
        failed = send_segments(transmit.payload, size, destination, controls)
        return true unless failed
      end
      sent = datagrams(transmit).map { |datagram| send_datagram(datagram, destination, controls) }
      if failed && GSO_REFUSED.any? { failed.is_a?(_1) }
        @gso = false if sent.any? || GSO_UNAVAILABLE.any? { failed.is_a?(_1) }
      end
      sent.all?
    end

    # The datagrams there now, RECEIVE_BATCH at most, each as [data,
    # [address, port] it came from, [address, port] it came to, ecn]; the
    # address it came to is nil where the OS does not tell it. None when
    # there are none.
    def receive
      received = [] #: Array[[String, address, address?, ecn]]
      while received.size < RECEIVE_BATCH
        result = @socket.recvmsg_nonblock(MAX_DATAGRAM, 0, exception: false)
        break unless result.is_a?(Array)
        data, from = result
        # The control messages follow the flags one by one, not as an Array
        # as the bundled declaration has it.
        controls = result.drop(3) #: Array[Socket::AncillaryData]
        received << [data, [unmapped(from.ip_address), from.ip_port], destination(controls), ecn(controls)]
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

    # The socket, so that IO.select waits on this with others, as a loop of
    # an application's own that reads several does.
    def to_io = @socket

    # All the datagrams in one sendmsg: nil when they went, else what it
    # failed with.
    private def send_segments(payload, size, destination, controls)
      segment = Socket::AncillaryData.new(@family, Socket::IPPROTO_UDP, UDP_SEGMENT, [size].pack("S"))
      @socket.sendmsg(payload, 0, destination, *controls, segment)
      nil
    rescue *GSO_REFUSED, *DROPPED => error
      error
    end

    private def send_datagram(datagram, destination, controls)
      @socket.sendmsg(datagram, 0, destination, *controls)
      true
    rescue *DROPPED
      false
    end

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

    # The control message that sends from the address of `source`, none to
    # leave it to the OS.
    private def source(source)
      return nil unless source
      address = Addrinfo.ip(mapped(source[0]))
      return Socket::AncillaryData.ipv6_pktinfo(address, 0) if @family == Socket::AF_INET6
      Socket::AncillaryData.ip_pktinfo(address, 0, address)
    end

    # The address a datagram came to, from its control messages, with the
    # socket's port.
    private def destination(controls)
      controls.each do |control|
        return [unmapped(control.ipv6_pktinfo[0].ip_address), @port] if control.cmsg_is?(Socket::IPPROTO_IPV6, Socket::IPV6_PKTINFO)
        return [control.ip_pktinfo[0].ip_address, @port] if control.cmsg_is?(Socket::IPPROTO_IP, Socket::IP_PKTINFO)
      end
      nil
    end

    # An IPv4 address as an IPv6 socket sends to or from it, IPv4-mapped,
    # which also marks it the IPv4 way.
    private def mapped(host) = @family == Socket::AF_INET6 && !host.include?(":") ? "::ffff:#{host}" : host

    # An IPv4-mapped address as the IPv4 address it maps.
    private def unmapped(host) = host.start_with?("::ffff:") && host.include?(".") ? host.delete_prefix("::ffff:") : host

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
