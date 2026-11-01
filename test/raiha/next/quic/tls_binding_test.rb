require "raiha/next/test_helper"
require "raiha/next/support/quic_tls"

# The handshake carried in CRYPTO frames, with the
# Machine's outputs and events told to the connection.
class RaihaNextQUICTLSBindingTest < Minitest::Test
  include NextQUICTLS

  # Keeps what the binding tells it.
  class Connection
    attr_reader :calls

    def initialize = @calls = []

    def install_keys(level, direction, secret:, suite:) = @calls << [:install_keys, level, direction]
    def peer_transport_parameters(data) = @calls << [:peer_transport_parameters, data]
    def handshake_completed(event) = @calls << [:handshake_completed, event.alpn]
    def tls_failed(code, reason) = @calls << [:tls_failed, code, reason]
    def tls_event(event) = @calls << [:tls_event, event.class]

    def of(name) = @calls.select { _1.first == name }
  end

  def parameters(cid) = QUIC::TransportParameters.new(initial_source_connection_id: cid)

  def client(connection, config: client_config)
    QUIC::TLSBinding.client(connection:, config:, keyring: client_keyring(config:), server_name: "localhost",
      transport_parameters: parameters("c".b * 8), time: NOW)
  end

  def server(connection, config: server_config)
    QUIC::TLSBinding.server(connection:, config:, keyring: server_keyring(config:), transport_parameters: parameters("s".b * 8),
      time: NOW, version: QUIC::Version::V1)
  end

  # Moves CRYPTO frames each way until neither has any.
  def exchange(*pair)
    20.times do
      moved = false
      [pair, pair.reverse].each do |from, to|
        %i[initial handshake one_rtt].each do |level|
          while (frame, _duty = from.next_crypto_frame(level, 1200))
            moved = true
            to.receive_crypto(level, frame, time: NOW)
          end
        end
      end
      break unless moved
    end
  end

  def test_a_handshake
    client_connection = Connection.new
    server_connection = Connection.new
    client = client(client_connection)
    assert client.crypto_pending?(:initial)
    server = server(server_connection)
    exchange(client, server)
    assert client.complete?
    assert server.complete?
    assert_equal [[:install_keys, :handshake, :read], [:install_keys, :handshake, :write], [:install_keys, :one_rtt, :read],
      [:install_keys, :one_rtt, :write]], client_connection.of(:install_keys).sort
    assert_equal [[:peer_transport_parameters, parameters("s".b * 8).encode]], client_connection.of(:peer_transport_parameters)
    assert_equal [[:peer_transport_parameters, parameters("c".b * 8).encode]], server_connection.of(:peer_transport_parameters)
    assert_equal [[:handshake_completed, "hq-interop"]], client_connection.of(:handshake_completed)
    assert_equal [[:handshake_completed, "hq-interop"]], server_connection.of(:handshake_completed)
    assert_empty client_connection.of(:tls_failed)
  end

  # A TLS failure is told as its error code: no ALPN in common is
  # no_application_protocol (120), CRYPTO_ERROR 0x178.
  def test_failure_as_an_error_code
    server_connection = Connection.new
    server = server(server_connection, config: server_config(alpn: ["h3"]))
    exchange(client(Connection.new), server)
    assert_equal [[:tls_failed, 0x178, :no_common_application_protocol]], server_connection.of(:tls_failed).map { [_1, _2, _3] }
  end

  # Bytes of a level TLS has left, past what it had received.
  def test_data_past_a_finished_level
    client = client(Connection.new)
    server = server(Connection.new)
    exchange(client, server)
    error = assert_raises(QUIC::Violation) { client.receive_crypto(:initial, QUIC::Wire::Frame::Crypto.new(offset: 100_000, data: "x".b), time: NOW) }
    assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, error.code
  end

  # More waiting than max(4096, what TLS allows for the level).
  def test_buffer_limit
    client = client(Connection.new)
    frame = QUIC::Wire::Frame::Crypto.new(offset: 1 << 20, data: "x".b)
    error = assert_raises(QUIC::Violation) { client.receive_crypto(:handshake, frame, time: NOW) }
    assert_equal QUIC::ErrorCode::CRYPTO_BUFFER_EXCEEDED, error.code
  end

  def test_a_tcp_profile_is_refused
    assert_raises(ArgumentError) { client(Connection.new, config: NextTLSPair.client_config(alpn: ALPN)) }
  end

  # A server given the ClientHello an Acceptor took does not read it again
  # when the frames that carried it are delivered once more.
  def test_a_client_hello_taken_already
    client = client(Connection.new)
    frames = []
    while (frame, _duty = client.next_crypto_frame(:initial, 1200))
      frames << frame
    end
    acceptor = TLS::Handshake::Acceptor.new
    frames.each { |frame| acceptor.receive(frame.data, epoch: :initial, now: NOW) }
    server_connection = Connection.new
    config = server_config
    server = QUIC::TLSBinding.server(connection: server_connection, config:, keyring: server_keyring(config:),
      transport_parameters: parameters("s".b * 8), time: NOW, version: QUIC::Version::V1, client_hello: acceptor.accepted)
    frames.each { |frame| server.receive_crypto(:initial, frame, time: NOW) }
    exchange(client, server)
    assert client.complete?
    assert server.complete?
    assert_empty server_connection.of(:tls_failed)
  end

  # A message of a level whose keys are gone is dropped, not an error.
  def test_a_message_of_a_discarded_level
    machine = Object.new
    def machine.each_output = yield(TLS::Output::Message.new(epoch: :initial, bytes: "x".b))
    def machine.each_event = nil
    binding = QUIC::TLSBinding.new(Connection.new, machine, TLS::Profile::QUIC)
    binding.discard_level(:initial)
    binding.pump
    refute binding.crypto_pending?(:initial)
  end

  # An empty frame past the end of a finished level carries no bytes past
  # it.
  def test_an_empty_frame_of_a_finished_level
    client = client(Connection.new)
    exchange(client, server(Connection.new))
    client.receive_crypto(:initial, QUIC::Wire::Frame::Crypto.new(offset: 100_000, data: "".b), time: NOW)
  end

  # Bytes of a level past a gap, still unread when TLS moves on from it.
  def test_bytes_left_behind
    client = client(Connection.new)
    frames = []
    while (frame, _duty = client.next_crypto_frame(:initial, 1200))
      frames << frame
    end
    server = server(Connection.new)
    total = frames.sum { _1.data.bytesize }
    server.receive_crypto(:initial, QUIC::Wire::Frame::Crypto.new(offset: total + 100, data: "x".b), time: NOW)
    *head, last = frames
    head.each { server.receive_crypto(:initial, _1, time: NOW) }
    error = assert_raises(QUIC::Violation) { server.receive_crypto(:initial, last, time: NOW) }
    assert_equal QUIC::ErrorCode::PROTOCOL_VIOLATION, error.code
  end
end
