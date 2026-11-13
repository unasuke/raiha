require "test_helper"
require "support/tcp_pair"

# Resumption over TCP: each ticket the server sends becomes a session the
# client may resume, of which the connection holds the newest 8 until
# they are taken.
class RaihaNextTLSTCPResumptionTest < Minitest::Test
  TLS = Raiha::TLS
  TCPPair = NextTCPPair
  TLSPair = NextTLSPair
  NOW = TCPPair::NOW
  SEED = "\x14".b * 32

  class Recorder
    attr_reader :values

    def initialize = @values = []

    def tls_trace(value) = @values << value
  end

  def server(**options) = TCPPair.server(config: TLSPair.server_config(ticket_key: SEED, **options))

  def sessions(connection) = TCPPair.events(connection).grep(TLS::Event::NewSessionTicket).map(&:session)

  def test_a_tcp_client_resumes
    session = sessions(TCPPair.connect(server: server).client).first
    pair = TCPPair.connect(client: TCPPair.client(session:), server: server)
    events = TCPPair.events(pair.client)
    assert events.grep(TLS::Event::HandshakeComplete).first.resumed
    assert_equal 2, events.grep(TLS::Event::NewSessionTicket).size
  end

  # A server that sends tickets without end: the client holds the newest 8,
  # and traces each it drops.
  def test_the_tickets_a_client_holds
    config = TLSPair.client_config
    tracer = Recorder.new
    client = TLS::TCP::Connection.client(config:, keyring: TLS::Keyring.client(config:), server_name: "localhost", now: NOW, tracer:)
    pair = TCPPair.connect(client:, server: server(ticket_count: 10))
    held = sessions(pair.client)
    assert_equal 8, held.size
    assert_equal (2..9).map { |i| [i].pack("Q>") }, held.map(&:ticket_nonce)
    assert_equal [TLS::Trace::TicketIgnored.new(reason: :too_many_tickets)] * 2, tracer.values.grep(TLS::Trace::TicketIgnored)
  end
end
