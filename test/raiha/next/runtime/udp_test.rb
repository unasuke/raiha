require "raiha/next/test_helper"
require "raiha/next/runtime"

# The UDP socket of the runtime on the loopback interface: each datagram
# goes with its ECN mark, IPv4 into a socket bound to "::" included, and
# comes out with the codepoint it was marked with.
class RaihaNextRuntimeUDPTest < Minitest::Test
  UDP = Raiha::Next::Runtime::UDP
  QUIC = Raiha::Next::QUIC

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

  def transmit(payload, to, ecn: :not_ect, segment_size: nil)
    QUIC::Transmit.new(payload:, destination: to, source: nil, ecn:, segment_size:)
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
    assert_equal [["not_ect", from, :not_ect], ["ect0", from, :ect0], ["ect1", from, :ect1]], received(receiver)
  end

  def test_each_codepoint_on_ipv6
    receiver = bind("::1")
    sender = bind("::1")
    %i[ect0 ect1].each { |ecn| sender.send(transmit(ecn.to_s.b, receiver.local_address, ecn:)) }
    assert_equal [["ect0", sender.local_address, :ect0], ["ect1", sender.local_address, :ect1]], received(receiver)
  end

  # A socket bound to "::" takes IPv4 from an IPv4-mapped address and
  # answers it there, keeping the mark both ways.
  def test_ipv4_into_a_socket_for_both
    server = bind("::")
    client = bind("127.0.0.1")
    client.send(transmit("hello".b, ["127.0.0.1", server.local_address[1]], ecn: :ect0))
    data, from, ecn = received(server).first
    assert_equal ["hello", ["::ffff:127.0.0.1", client.local_address[1]], :ect0], [data, from, ecn]

    server.send(transmit("world".b, from, ecn: :ect1))
    assert_equal [["world", ["127.0.0.1", server.local_address[1]], :ect1]], received(client)
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

  def test_a_batch_has_a_limit
    receiver = bind("127.0.0.1")
    sender = bind("127.0.0.1")
    (UDP::RECEIVE_BATCH + 3).times { sender.send(transmit("x".b, receiver.local_address)) }
    assert_equal UDP::RECEIVE_BATCH, received(receiver).size
    assert_equal 3, receiver.receive.size
    assert_empty receiver.receive
  end

  # A datagram larger than UDP carries is dropped, not raised.
  def test_a_datagram_too_big
    receiver = bind("127.0.0.1")
    sender = bind("127.0.0.1")
    refute sender.send(transmit("x".b * 70_000, receiver.local_address))
    refute receiver.wait_readable(0.05)
  end
end
