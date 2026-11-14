require "test_helper"
require "raiha/runtime"

# The UDP socket of the runtime on the loopback interface: each datagram
# goes with its ECN mark, IPv4 into a socket bound to "::" included, and
# comes out with the codepoint it was marked with and the address it came
# to, IPv4's told as IPv4's; a Transmit with a source goes from there;
# the datagrams of a Transmit go in one with GSO, and one by one where it
# is refused.
class RaihaRuntimeUDPTest < Minitest::Test
  UDP = Raiha::Runtime::UDP
  QUIC = Raiha::QUIC

  def setup
    @sockets = []
  end

  def teardown
    @sockets.each { _1.close unless _1.closed? }
  end

  def bind(host)
    UDP.bind(host, 0).tap { @sockets << _1 }
  rescue Errno::EADDRNOTAVAIL, Errno::EAFNOSUPPORT
    skip "#{host} cannot be bound here"
  end

  def transmit(payload, to, ecn: :not_ect, segment_size: nil, source: nil)
    QUIC::Transmit.new(payload:, destination: to, source:, ecn:, segment_size:)
  end

  # What `socket` has received within a second.
  def received(socket)
    assert socket.wait_readable(1), "nothing came"
    socket.receive
  end

  def test_each_codepoint_on_ipv4
    receiver = bind("127.0.0.1")
    sender = bind("127.0.0.1")
    %i[not_ect ect0 ect1].each { |ecn| assert sender.send(transmit(ecn.to_s.b, receiver.local_address, ecn:)) }
    from = sender.local_address
    to = receiver.local_address
    assert_equal [["not_ect", from, to, :not_ect], ["ect0", from, to, :ect0], ["ect1", from, to, :ect1]], received(receiver)
  end

  def test_each_codepoint_on_ipv6
    receiver = bind("::1")
    sender = bind("::1")
    %i[ect0 ect1].each { |ecn| sender.send(transmit(ecn.to_s.b, receiver.local_address, ecn:)) }
    from = sender.local_address
    to = receiver.local_address
    assert_equal [["ect0", from, to, :ect0], ["ect1", from, to, :ect1]], received(receiver)
  end

  # A socket bound to "::" takes IPv4, tells its addresses as IPv4's,
  # which a socket of IPv4 alone would tell alike, and answers there,
  # keeping the mark both ways.
  def test_ipv4_into_a_socket_for_both
    server = bind("::")
    client = bind("127.0.0.1")
    client.send(transmit("hello".b, ["127.0.0.1", server.local_address[1]], ecn: :ect0))
    data, from, to, ecn = received(server).first
    assert_equal ["hello", client.local_address, ["127.0.0.1", server.local_address[1]], :ect0], [data, from, to, ecn]

    server.send(transmit("world".b, from, ecn: :ect1))
    assert_equal [["world", ["127.0.0.1", server.local_address[1]], client.local_address, :ect1]], received(client)
  end

  # A socket bound to every address tells the one a datagram came to, and
  # answers from it when the Transmit names it, IPv4 into a socket for both
  # included; the OS would answer the loopback's 127.0.0.1 from itself.
  def test_the_address_a_datagram_came_to_and_answers_from
    skip "127.0.0.2 is Linux's loopback" unless RUBY_PLATFORM.include?("linux")
    %w[0.0.0.0 ::].each do |host|
      server = bind(host)
      client = bind("127.0.0.1")
      port = server.local_address[1]
      client.send(transmit("hello".b, ["127.0.0.2", port]))
      _, from, to, = received(server).first
      assert_equal ["127.0.0.2", port], to, host
      server.send(transmit("world".b, from, source: to))
      assert_equal [["world", ["127.0.0.2", port], client.local_address, :not_ect]], received(client), host
    end
  end

  # A datagram goes from a socket from its own address and port, or any
  # address of its family on its port when bound to "0.0.0.0", any address
  # at all when bound to "::".
  def test_what_a_socket_sends_from
    specific = bind("127.0.0.1")
    port = specific.local_address[1]
    assert specific.sends_from?(["127.0.0.1", port])
    refute specific.sends_from?(["127.0.0.2", port])
    refute specific.sends_from?(["127.0.0.1", port + 1])
    ipv4 = bind("0.0.0.0")
    port = ipv4.local_address[1]
    assert ipv4.sends_from?(["192.0.2.1", port])
    refute ipv4.sends_from?(["2001:db8::1", port])
    both = bind("::")
    port = both.local_address[1]
    assert both.sends_from?(["192.0.2.1", port])
    assert both.sends_from?(["2001:db8::1", port])
    refute both.sends_from?(["2001:db8::1", port + 1])
  end

  # A peer can mark congestion; the codepoint is the low two bits of the
  # traffic class, whatever the rest says.
  def test_congestion_experienced_and_the_rest_of_the_class
    receiver = bind("127.0.0.1")
    raw = UDPSocket.new.tap { @sockets << _1 }
    to = Socket.sockaddr_in(receiver.local_address[1], "127.0.0.1")
    raw.sendmsg("ce", 0, to, Socket::AncillaryData.int(:INET, :IP, :TOS, 0b11))
    raw.sendmsg("dscp", 0, to, Socket::AncillaryData.int(:INET, :IP, :TOS, 0xb8 | 0b10))
    assert_equal [:ce, :ect0], received(receiver).map(&:last)
  end

  def test_a_transmit_of_several_datagrams
    receiver = bind("127.0.0.1")
    sender = bind("127.0.0.1")
    sender.send(transmit("a".b * 1200 + "b".b * 1200 + "c".b * 500, receiver.local_address, segment_size: 1200))
    assert_equal ["a" * 1200, "b" * 1200, "c" * 500], received(receiver).map(&:first)
  end

  # The datagrams of a Transmit, cut by the kernel, each marked.
  def test_a_transmit_of_several_datagrams_marked
    receiver = bind("::")
    sender = bind("::")
    assert sender.send(transmit("a".b * 1200 + "b".b * 600, ["::ffff:127.0.0.1", receiver.local_address[1]], ecn: :ect0, segment_size: 1200))
    assert_equal [["a" * 1200, :ect0], ["b" * 600, :ect0]], received(receiver).map { [_1.first, _1.last] }
  end

  # A socket that refuses the datagrams of a Transmit in one with `error`,
  # and each of them too when `everything`, counting what it was asked.
  class RefusingSocket
    attr_reader :segmented, :datagrams

    def initialize(error, everything: false)
      @error = error
      @everything = everything
      @segmented = 0
      @datagrams = []
    end

    def local_address = Addrinfo.udp("127.0.0.1", 4433)

    def setsockopt(*) = nil

    def getsockopt(*) = Socket::Option.int(:INET, :SOCKET, :RCVBUF, 0)

    def sendmsg(data, _flags, _destination, *controls)
      if controls.any? { _1.level == Socket::IPPROTO_UDP }
        @segmented += 1
        raise @error
      end
      raise @error if @everything
      @datagrams << data
      data.bytesize
    end
  end

  # Where GSO is refused, as with no checksum offload (EIO), the datagrams
  # go one by one, and the socket does not try it again.
  def test_gso_refused
    skip "GSO is Linux's" unless RUBY_PLATFORM.include?("linux")
    payload = "a".b * 1200 + "b".b * 1200 + "c".b * 500
    [Errno::EIO, Errno::ENOPROTOOPT, Errno::EINVAL, Errno::EMSGSIZE].each do |error|
      socket = RefusingSocket.new(error)
      udp = UDP.new(socket)
      2.times { assert udp.send(transmit(payload, ["127.0.0.1", 4434], segment_size: 1200)) }
      assert_equal [1, ["a" * 1200, "b" * 1200, "c" * 500] * 2], [socket.segmented, socket.datagrams], error.name
    end
  end

  # EINVAL that comes one by one all the same is the destination's, a port
  # of 0 say: the datagrams are dropped, and GSO is tried again next time.
  def test_einval_of_the_destination
    skip "GSO is Linux's" unless RUBY_PLATFORM.include?("linux")
    socket = RefusingSocket.new(Errno::EINVAL, everything: true)
    udp = UDP.new(socket)
    2.times { refute udp.send(transmit("x".b * 2400, ["127.0.0.1", 0], segment_size: 1200)) }
    assert_equal 2, socket.segmented
  end

  # A socket that raises the next of `errors` at each sendmsg, nil for
  # none, and keeps what went: a GSO payload whole.
  class ScriptedSocket
    attr_reader :segmented, :sent

    def initialize(*errors)
      @errors = errors
      @segmented = 0
      @sent = []
    end

    def local_address = Addrinfo.udp("127.0.0.1", 4433)

    def setsockopt(*) = nil

    def getsockopt(*) = Socket::Option.int(:INET, :SOCKET, :RCVBUF, 0)

    def sendmsg(data, _flags, _destination, *controls)
      @segmented += 1 if controls.any? { _1.level == Socket::IPPROTO_UDP }
      error = @errors.shift
      raise error if error
      @sent << data
      data.bytesize
    end
  end

  # A kernel short of buffers (ENOBUFS) for the whole of a GSO send: the
  # datagrams go one by one, and the next Transmit tries GSO again.
  def test_gso_short_of_buffers
    skip "GSO is Linux's" unless RUBY_PLATFORM.include?("linux")
    payload = "a".b * 1200 + "b".b * 1200 + "c".b * 500
    socket = ScriptedSocket.new(Errno::ENOBUFS)
    udp = UDP.new(socket)
    2.times { assert udp.send(transmit(payload, ["127.0.0.1", 4434], segment_size: 1200)) }
    assert_equal [2, ["a" * 1200, "b" * 1200, "c" * 500, payload]], [socket.segmented, socket.sent]
  end

  # One datagram lost one by one loses only itself; one that went shows the
  # destination takes them, and GSO, refused, is not tried again.
  def test_one_by_one_past_a_datagram_lost
    skip "GSO is Linux's" unless RUBY_PLATFORM.include?("linux")
    payload = "a".b * 1200 + "b".b * 1200 + "c".b * 500
    socket = ScriptedSocket.new(Errno::EINVAL, nil, Errno::ENOBUFS)
    udp = UDP.new(socket)
    refute udp.send(transmit(payload, ["127.0.0.1", 4434], segment_size: 1200))
    assert udp.send(transmit(payload, ["127.0.0.1", 4434], segment_size: 1200))
    assert_equal [1, ["a" * 1200, "c" * 500, "a" * 1200, "b" * 1200, "c" * 500]], [socket.segmented, socket.sent]
  end

  # The Config of a runtime: MAX_TRANSMIT for max_transmit_size, unless the
  # application chose one.
  # IO.select waits on sockets of the runtime together.
  def test_waiting_on_several
    first = bind("127.0.0.1")
    second = bind("127.0.0.1")
    first.send(transmit("hello".b, second.local_address))
    ready, = IO.select([first, second], nil, nil, 1)
    assert_equal [second], ready
  end

  def test_batching
    assert_equal UDP::MAX_TRANSMIT, UDP.batching(QUIC::Config.new).max_transmit_size
    assert_equal 1200, UDP.batching(QUIC::Config.new(max_transmit_size: 1200)).max_transmit_size
  end

  # On Linux, IP fragments nothing a socket sends, at both levels of one
  # bound to "::".
  def test_no_fragments
    skip "PMTUDISC_PROBE is Linux's" unless UDP.unfragmented?
    ip = [Socket::IPPROTO_IP, Socket::IP_MTU_DISCOVER]
    { "127.0.0.1" => [ip], "::" => [ip, [Socket::IPPROTO_IPV6, Socket::IPV6_MTU_DISCOVER]] }.each do |host, options|
      socket = bind(host).instance_variable_get(:@socket)
      options.each { |level, name| assert_equal UDP::PMTUDISC_PROBE, socket.getsockopt(level, name).int, host }
    end
  end

  # Where a socket cannot keep IP from fragmenting, a Config probes no
  # path; where it can, the Config is as it was.
  def test_pmtud
    config = QUIC::Config.new
    assert_same config, UDP.pmtud(config) if UDP.unfragmented?
    unfragmented = UDP.method(:unfragmented?)
    UDP.define_singleton_method(:unfragmented?) { false }
    assert_equal [false, false], [UDP.pmtud(config).enable_pmtud, UDP.pmtud(config.with(enable_pmtud: false)).enable_pmtud]
  ensure
    UDP.define_singleton_method(:unfragmented?, unfragmented) if unfragmented
  end

  def test_a_batch_has_a_limit
    receiver = bind("127.0.0.1")
    sender = bind("127.0.0.1")
    (UDP::RECEIVE_BATCH + 3).times { sender.send(transmit("x".b, receiver.local_address)) }
    assert_equal UDP::RECEIVE_BATCH, received(receiver).size
    assert_equal 3, receiver.receive.size
    assert_empty receiver.receive
  end

  # A peer that spoofs its source chooses where a response goes; one the OS
  # will not send to is dropped, not raised.
  def test_a_destination_the_os_refuses
    sender = bind("::")
    refute sender.send(transmit("x".b, ["::ffff:127.0.0.1", 0]))
    refute sender.send(transmit("x".b, ["::ffff:255.255.255.255", 443]))
    refute bind("127.0.0.1").send(transmit("x".b, ["127.0.0.1", 0], ecn: :ect0))
    refute bind("127.0.0.1").send(transmit("x".b, ["::1", 443]))
  end

  # A datagram larger than UDP carries is dropped, not raised.
  def test_a_datagram_too_big
    receiver = bind("127.0.0.1")
    sender = bind("127.0.0.1")
    refute sender.send(transmit("x".b * 70_000, receiver.local_address))
    refute receiver.wait_readable(0.05)
  end

  # Sockets that reuse the port bind the same one, the port 0 gave the
  # first included, and the kernel gives each the datagrams of some
  # senders; without it the second does not bind.
  def test_sockets_that_reuse_a_port
    skip "SO_REUSEPORT spreads datagrams on Linux alone" unless RUBY_PLATFORM.include?("linux")
    first = UDP.bind("127.0.0.1", 0, reuse_port: true).tap { @sockets << _1 }
    port = first.local_address.fetch(1)
    second = UDP.bind("127.0.0.1", port, reuse_port: true).tap { @sockets << _1 }
    assert_equal port, second.local_address.fetch(1)
    assert_raises(Errno::EADDRINUSE) { UDP.bind("127.0.0.1", port) }
    32.times { bind("127.0.0.1").send(transmit("x".b, ["127.0.0.1", port])) }
    counts = [first, second].map { |socket| socket.wait_readable(0.2) ? (socket.receive.size + drain(socket)) : 0 }
    assert_equal 32, counts.sum
    assert counts.all?(&:positive?), "each socket takes some senders: #{counts}"
  end

  # How many more datagrams `socket` has waiting.
  def drain(socket)
    count = 0
    count += socket.receive.size while socket.wait_readable(0.05)
    count
  end
end
