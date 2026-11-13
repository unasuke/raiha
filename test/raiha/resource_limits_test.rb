require "test_helper"
require "raiha/runtime"

# The bounds of what a peer can make each layer keep, as the design
# document's table of them ("資源の上限") gives them: a value changed in
# the code is to be changed in the table as well, and this fails until it
# is. Whether each bound holds is the test of its own layer.
class RaihaNextResourceLimitsTest < Minitest::Test
  CONSTANTS = {
    # TLS
    "TLS::Handshake::Acceptor::MAX_CLIENT_HELLO_SIZE" => 16 * 1024,
    "TLS::Config::MAX_TICKET_SIZE" => 12_288,
    "TLS::Config::DEFAULT_MAX_TICKET_SIZE" => 8192,
    "TLS::Config::MAX_TICKET_LIFETIME" => 604_800,
    "TLS::Handshake::KeyUpdateHandling::MAX_CONSECUTIVE_KEY_UPDATES" => 32,
    "TLS::Record::MAX_PLAINTEXT" => 16 * 1024,
    "TLS::TCP::Acceptor::MAX_HELD_BYTES" => 64 * 1024,
    "TLS::TCP::Connection::WRITE_BUFFER_LIMIT" => 64 * 1024,
    "TLS::TCP::Connection::MAX_HELD_TICKETS" => 8,
    "TLS::TicketKeys::Ratchet::MAX_STEPS" => 4096,
    "TLS::AntiReplay::WINDOW" => 11,
    # QUIC, a connection
    "QUIC::Connection::MAX_EVENTS" => 4096,
    "QUIC::Connection::MAX_HELD_TICKETS" => 8,
    "QUIC::Connection::MAX_VALIDATING_PATHS" => 3,
    "QUIC::Connection::MAX_REASON_LENGTH" => 256,
    "QUIC::KeptPackets::PACKETS" => 10,
    "QUIC::KeptPackets::BYTES" => 16 * 1024,
    "QUIC::TLSBinding::MIN_CRYPTO_BUFFER" => 4096,
    "QUIC::CryptoStream::MAX_RANGES" => 1000,
    "QUIC::Recovery::MAX_ACK_RANGES" => 64,
    "QUIC::Recovery::MAX_NON_ACK_ELICITING_TAIL" => 1000,
    "QUIC::Recovery::MAX_LOST_PACKETS" => 64,
    "QUIC::IssuedConnectionIDs::MAX" => 8,
    "QUIC::IssuedConnectionIDs::MAX_RETIRED" => 16,
    "QUIC::Datagrams::MAX_SEND_QUEUE" => 32,
    "QUIC::Datagrams::MAX_RECEIVED" => 128,
    "QUIC::Datagrams::MAX_RECEIVED_BYTES" => 1024 * 1024,
    "QUIC::Qlog::Tracer::DEFAULT_MAX_BYTES" => 64 * 1024 * 1024,
    # QUIC, an Endpoint
    "QUIC::Endpoint::HANDLE_LIFETIME" => 10.0,
    "QUIC::Endpoint::HANDLE_BUFFER" => 64 * 1024,
    "QUIC::Endpoint::HANDLES_BUFFER" => 16 * 1024 * 1024,
    "QUIC::Endpoint::RESET_ADDRESSES" => 1024,
    "QUIC::Endpoint::RESET_BURST" => 10.0,
    "QUIC::Endpoint::RESET_TOTAL_BURST" => 1000.0,
    # HTTP/3 and QPACK
    "HTTP3::Connection::MAX_EVENTS" => 4096,
    "HTTP3::Connection::MAX_CONTROL_FRAME" => 16 * 1024,
    "HTTP3::Connection::MAX_WAITING" => 1024,
    "HTTP3::Connection::MAX_PENDING_PRIORITIES" => 128,
    "HTTP3::Connection::MAX_DATAGRAMS" => 32,
    "HTTP3::Connection::MAX_CAPSULE" => 64 * 1024,
    "HTTP3::Connection::DEFAULT_MAX_SEND_BUFFER" => 64 * 1024,
    "HTTP3::QPACK::Decoder::DEFAULT_MAX_FIELD_SECTION_SIZE" => 65_536,
    "HTTP3::Qlog::Tracer::MAX_FIELD_BYTES" => 256,
    "HTTP3::Qlog::Tracer::MAX_FIELDS" => 64,
    # Runtime
    "Runtime::Server::MAX_CONNECTIONS" => 1024,
    "Runtime::Worker::QUEUE" => 1024,
    "Runtime::Worker::QUEUE_BYTES" => 4 * 1024 * 1024,
    "Runtime::Session::MAX_HELD" => 8,
    "Runtime::HTTP3::Exchange::MAX_UNREAD" => 256 * 1024,
    "Runtime::Qlog::BUDGET" => 1024 * 1024 * 1024,
    "Runtime::Qlog::MAX_FILES" => 4096,
    "Runtime::UDP::BUFFER" => 8 * 1024 * 1024
  }.freeze

  # The defaults of the settings that bound what a peer can make a
  # connection keep.
  SETTINGS = {
    "QUIC::Config#initial_max_data" => 768 * 1024,
    "QUIC::Config#max_receive_window" => 15 * 1024 * 1024,
    "QUIC::Config#max_stream_receive_window" => 6 * 1024 * 1024,
    "QUIC::Config#initial_max_streams_bidi" => 100,
    "QUIC::Config#initial_max_streams_uni" => 100,
    "QUIC::Config#active_connection_id_limit" => 8,
    "TLS::Config#max_handshake_message_size" => 16 * 1024,
    "TLS::Config#max_certificate_message_size" => 256 * 1024,
    "TLS::Config#max_certificate_chain_length" => 10,
    "HTTP3::Settings#qpack_max_table_capacity" => 0,
    "HTTP3::Settings#qpack_blocked_streams" => 0,
    "HTTP3::Settings#max_field_section_size" => 65_536
  }.freeze

  def test_the_constants
    CONSTANTS.each do |name, value|
      assert_equal value, Raiha.const_get(name), name
    end
  end

  def test_the_defaults
    defaults = {
      "QUIC::Config" => Raiha::QUIC::Config.new,
      "TLS::Config" => Raiha::TLS::Config.client,
      "HTTP3::Settings" => Raiha::HTTP3::Settings.new
    }
    SETTINGS.each do |name, value|
      owner, setting = name.split("#")
      assert_equal value, defaults.fetch(owner).public_send(setting), name
    end
  end

  # A server's default max_unvalidated is half its max_connections.
  def test_max_unvalidated
    server = Raiha::Runtime::Server.new(config: Raiha::QUIC::Config.new, tls_config: Raiha::TLS::Config.server,
      keyring: nil)
    assert_equal Raiha::Runtime::Server::MAX_CONNECTIONS / 2, server.instance_variable_get(:@max_unvalidated)
  end
end
