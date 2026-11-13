# frozen_string_literal: true

require "socket"

module Raiha::Runtime
  # A UDP socket that carries QUIC: the datagrams of a Transmit go out, on
  # Linux, in one `sendmsg` that the kernel cuts at the segment size (GSO,
  # UDP_SEGMENT), elsewhere each with its own, marked with its ECN
  # codepoint; each datagram that comes in is read with `recvmsg` along with
  # the codepoint it was marked with and the address it came to (IP_PKTINFO,
  # or IP_RECVDSTADDR on the BSDs, and IPV6_PKTINFO), so far as the OS
  # tells them (UDP#features), and one sent from an address of the
  # Transmit's goes from there by a control message too. Bound to "::",
  # one socket takes IPv4 as well where the OS lets it (not OpenBSD); the
  # addresses of IPv4 it tells are IPv4's ("192.0.2.1", not the IPv4-mapped
  # "::ffff:192.0.2.1"), so that a peer is the same address whichever
  # socket it came on, and it maps them back to send.
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
    # burst: the kernel drops what overflows before it is read. Linux cuts
    # a larger size down to its limit; OpenBSD refuses one over its limit
    # (2 MiB) with ENOBUFS, and the socket asks for half as much, and half
    # again, while it is more than the buffer has.
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
    # What sendmsg refuses a control message it does not take with; the
    # datagram goes again without it (UDP#without_controls).
    CONTROLS_REFUSED = [Errno::EINVAL, Errno::ENOPROTOOPT, Errno::EOPNOTSUPP].freeze
    # The most a Transmit carries for GSO: the largest UDP payload over
    # IPv4, a Config's max_transmit_size when the application leaves it.
    MAX_TRANSMIT = 65_507

    # What a socket has here: the sizes of its buffers as the OS keeps
    # them, whether it takes IPv4, and the control messages it uses now,
    # those it reads (the ECN codepoint and the address a datagram came
    # to) and those it sends (the address and the ECN mark a datagram goes
    # with). The runtime logs none of this; it is there to look at a socket
    # on an OS that differs.
    Features = Data.define(:receive_buffer, :send_buffer, :ipv4, :ecn_in, :destination, :source, :ecn_out)

    # `config` with MAX_TRANSMIT for max_transmit_size, unless it has one:
    # a socket here sends the datagrams of a Transmit as they are cut.
    def self.batching(config) = config.max_transmit_size ? config : config.with(max_transmit_size: MAX_TRANSMIT)

    # Whether a socket here keeps IP from fragmenting what it sends.
    def self.unfragmented? = RUBY_PLATFORM.include?("linux") && Socket.const_defined?(:IP_MTU_DISCOVER) &&
      Socket.const_defined?(:IPV6_MTU_DISCOVER)

    # `config` with enable_pmtud false where a socket cannot keep IP from
    # fragmenting, so that no probe passes in pieces.
    def self.pmtud(config) = unfragmented? || !config.enable_pmtud ? config : config.with(enable_pmtud: false)

    # `config` without ECN on IPv4 where the OS has no IP_RECVTOS, so that
    # QUIC sends Not-ECT there: such an OS, OpenBSD, also skips an IP_TOS
    # control message without a word, and QUIC would take what it sent for
    # ECT(0).
    def self.ecn(config)
      return config if Socket.const_defined?(:IP_RECVTOS)
      config.with(ecn_address_families: config.ecn_address_families - %i[ipv4])
    end

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
      if family == Socket::AF_INET6
        begin
          socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, 0)
        rescue Errno::EINVAL, Errno::ENOPROTOOPT
          # OpenBSD's IPv6 sockets are IPv6's alone (ip6(4)), and the socket
          # takes no IPv4 (UDP.takes_ipv4?).
        end
      end
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
      enlarge(Socket::SO_RCVBUF)
      enlarge(Socket::SO_SNDBUF)
      # What a datagram comes with, at both levels on a socket that takes
      # both, the options Socket names here alone: an IPv6 socket that
      # takes IPv4 tells the codepoint and the address of an IPv4 datagram
      # the IPv4 way. The IPv4 options go only on a socket that takes IPv4,
      # as OpenBSD's IPv6 sockets refuse them (EINVAL). Its IPv4 has no
      # IP_RECVTOS, and IP_RECVDSTADDR in place of IP_PKTINFO.
      ipv4 = takes_ipv4?
      ipv6 = @family == Socket::AF_INET6
      @ipv4_destination = if !ipv4 then nil
        elsif enable(Socket::IPPROTO_IP, :IP_PKTINFO) then Socket::IP_PKTINFO
        elsif enable(Socket::IPPROTO_IP, :IP_RECVDSTADDR) then Socket::IP_RECVDSTADDR
        end
      ipv6_destination = ipv6 && enable(Socket::IPPROTO_IPV6, :IPV6_RECVPKTINFO)
      ipv4_ecn = ipv4 && enable(Socket::IPPROTO_IP, :IP_RECVTOS)
      ipv6_ecn = ipv6 && enable(Socket::IPPROTO_IPV6, :IPV6_RECVTCLASS)
      @destination = (!ipv4 || !@ipv4_destination.nil?) && (!ipv6 || ipv6_destination)
      @ecn_in = (!ipv4 || ipv4_ecn) && (!ipv6 || ipv6_ecn)
      # No fragments, at both levels on a socket that sends both.
      if UDP.unfragmented?
        @socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_MTU_DISCOVER, PMTUDISC_PROBE)
        @socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_MTU_DISCOVER, PMTUDISC_PROBE) if @family == Socket::AF_INET6
      end
      @gso = RUBY_PLATFORM.include?("linux")
      # The control messages a datagram goes with: the ECN mark of IPv4
      # only where the codepoint is read too (UDP.ecn), and the source of
      # IPv4 by IP_PKTINFO or else IP_SENDSRCADDR. A kind sendmsg refuses
      # is left out for good (without_controls).
      @sends = { tos: ipv4 && Socket.const_defined?(:IP_RECVTOS), tclass: ipv6,
                 ip_source: ipv4 && (Socket.const_defined?(:IP_PKTINFO) || Socket.const_defined?(:IP_SENDSRCADDR)),
                 ipv6_source: ipv6 }
    end

    # The Features of this socket now.
    def features
      Features.new(receive_buffer: @socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF).int,
        send_buffer: @socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF).int, ipv4: takes_ipv4?,
        ecn_in: @ecn_in, destination: @destination, source: @sends[@family == Socket::AF_INET6 ? :ipv6_source : :ip_source],
        ecn_out: (!takes_ipv4? || @sends[:tos]) && (@family != Socket::AF_INET6 || @sends[:tclass]))
    end

    # [address, port] the socket is bound to.
    def local_address
      address = @socket.local_address
      [address.ip_address, address.ip_port]
    end

    # Whether a datagram from `address` ([address, port]) goes from this
    # socket: the port is the socket's, and so is the address, or the
    # socket is bound to any of its family, IPv4 too for "::" where IPv4
    # comes to it.
    def sends_from?(address) = UDP.covers?(@socket, address)

    # Whether `socket`, a socket wrapped or not yet, sends from `address`,
    # as `sends_from?` tells of one.
    def self.covers?(socket, address)
      host, port = address
      bound = socket.local_address
      return false unless port == bound.ip_port
      return host.include?(":") || takes_ipv4?(socket) if bound.ipv6? && bound.ipv6_unspecified?
      return !host.include?(":") if bound.ip_address == "0.0.0.0"
      UDP.unmapped(bound.ip_address) == host
    end

    # Whether IPv4 comes to this socket (UDP.takes_ipv4?).
    def takes_ipv4? = UDP.takes_ipv4?(@socket)

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
        failed = send_segments(transmit.payload, size, destination, controls.map(&:last))
        return true unless failed
      end
      sends = @sends.dup
      sent = datagrams(transmit).map { |datagram| send_datagram(datagram, destination, controls) }
      # A control message the datagrams went without was at fault, not GSO.
      if failed && GSO_REFUSED.any? { failed.is_a?(_1) } && @sends == sends
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

    # Sets the buffer `option` to BUFFER, or to the most of its halves the
    # OS takes; never less than the buffer has.
    private def enlarge(option)
      size = BUFFER
      default = @socket.getsockopt(Socket::SOL_SOCKET, option).int
      while size > default && size.positive?
        begin
          return @socket.setsockopt(Socket::SOL_SOCKET, option, size)
        rescue Errno::ENOBUFS, Errno::EINVAL
          size /= 2
        end
      end
    end

    # Turns on the option `name` at `level` where Socket names it; whether
    # it did.
    private def enable(level, name)
      return false unless Socket.const_defined?(name)
      @socket.setsockopt(level, Socket.const_get(name), 1)
      true
    end

    # Whether IPv4 comes to `socket`: one bound to an address of IPv4, or
    # of IPv6 bound to "::" (or an IPv4-mapped address) and not IPv6 alone,
    # which OpenBSD does not allow.
    def self.takes_ipv4?(socket)
      local = socket.local_address
      return true if local.ipv4?
      return false unless local.ipv6_unspecified? || local.ipv6_v4mapped?
      socket.getsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY).int.zero?
    end

    # All the datagrams in one sendmsg: nil when they went, else what it
    # failed with.
    private def send_segments(payload, size, destination, controls)
      segment = Socket::AncillaryData.new(@family, Socket::IPPROTO_UDP, UDP_SEGMENT, [size].pack("S"))
      @socket.sendmsg(payload, 0, destination, *controls, segment)
      nil
    rescue *GSO_REFUSED, *DROPPED => error
      error
    end

    # `controls` are [kind, control message], those of a kind left out
    # since dropped.
    private def send_datagram(datagram, destination, controls)
      controls = controls.select { |kind, _| @sends[kind] }
      @socket.sendmsg(datagram, 0, destination, *controls.map(&:last))
      true
    rescue *CONTROLS_REFUSED
      without_controls(datagram, destination, controls)
    rescue *DROPPED
      false
    end

    # Sends `datagram`, which sendmsg refused with `controls`, without the
    # ECN mark, then without the source, then without both; what it goes
    # without is left out for good. When it never goes, the destination is
    # at fault, and nothing is left out.
    private def without_controls(datagram, destination, controls)
      marks, sources = controls.partition { |kind, _| kind == :tos || kind == :tclass }
      trials = [] #: Array[[Array[[Symbol, Socket::AncillaryData]], Array[[Symbol, Socket::AncillaryData]]]]
      trials << [sources, marks] unless marks.empty?
      trials << [marks, sources] unless sources.empty?
      trials << [[], controls] unless marks.empty? || sources.empty?
      trials.each do |kept, left|
        @socket.sendmsg(datagram, 0, destination, *kept.map(&:last))
        left.each { |kind, _| @sends[kind] = false }
        return true
      rescue *CONTROLS_REFUSED
        next
      rescue *DROPPED
        return false
      end
      false
    end

    private def datagrams(transmit)
      payload = transmit.payload
      size = transmit.segment_size
      return [payload] unless size && size < payload.bytesize
      (0...payload.bytesize).step(size).map { |offset| payload.byteslice(offset, size) || "".b }
    end

    # [kind, control message] that marks a datagram to `host` with `ecn`,
    # none when it goes without.
    private def mark(ecn, host)
      value = MARKS[ecn] or return nil
      if @family == Socket::AF_INET6 && !(host.start_with?("::ffff:") && host.include?("."))
        [:tclass, Socket::AncillaryData.int(:INET6, :IPV6, :TCLASS, value)] if @sends[:tclass]
      elsif @sends[:tos]
        [:tos, Socket::AncillaryData.int(:INET, :IP, :TOS, value)]
      end
    end

    # [kind, control message] that sends from the address of `source`,
    # none to leave it to the OS. IP_SENDSRCADDR carries the in_addr alone.
    private def source(source)
      return nil unless source
      address = Addrinfo.ip(mapped(source[0]))
      if @family == Socket::AF_INET6
        [:ipv6_source, Socket::AncillaryData.ipv6_pktinfo(address, 0)] if @sends[:ipv6_source]
      elsif !@sends[:ip_source] then nil
      elsif Socket.const_defined?(:IP_PKTINFO)
        [:ip_source, Socket::AncillaryData.ip_pktinfo(address, 0, address)]
      else
        [:ip_source, Socket::AncillaryData.new(:INET, :IP, Socket::IP_SENDSRCADDR, address.ip_address.split(".").map(&:to_i).pack("C4"))]
      end
    end

    # The address a datagram came to, from its control messages, with the
    # socket's port.
    private def destination(controls)
      controls.each do |control|
        return [unmapped(control.ipv6_pktinfo[0].ip_address), @port] if control.cmsg_is?(Socket::IPPROTO_IPV6, Socket::IPV6_PKTINFO)
        return [ipv4_destination(control), @port] if @ipv4_destination && control.cmsg_is?(Socket::IPPROTO_IP, @ipv4_destination) # steep:ignore
      end
      nil
    end

    # The address of IP_PKTINFO's in_pktinfo, or IP_RECVDSTADDR's in_addr,
    # which is the address alone.
    private def ipv4_destination(control)
      data = control.data
      data.bytesize == 4 ? data.unpack("C4").join(".") : control.ip_pktinfo[0].ip_address
    end

    # An IPv4 address as an IPv6 socket sends to or from it, IPv4-mapped,
    # which also marks it the IPv4 way.
    private def mapped(host) = @family == Socket::AF_INET6 && !host.include?(":") ? "::ffff:#{host}" : host

    # An IPv4-mapped address as the IPv4 address it maps.
    private def unmapped(host) = UDP.unmapped(host)

    # `host` as IPv4's when it is IPv4-mapped.
    def self.unmapped(host) = host.start_with?("::ffff:") && host.include?(".") ? host.delete_prefix("::ffff:") : host

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
