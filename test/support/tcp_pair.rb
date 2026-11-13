require "support/tls_pair"

# Two TCP::Connections of raiha, joined without a
# socket: what one outputs, the other receives.
module TCPPair
  TLS = Raiha::TLS
  TLSPair = ::TLSPair
  NOW = TLSPair::NOW

  Pair = Data.define(:client, :server)

  module_function

  def client(config: TLSPair.client_config, server_name: "localhost", keylog: nil, session: nil, early_data: false, now: NOW,
    **keyring_options)
    TLS::TCP::Connection.client(config:, keyring: TLS::Keyring.client(config:, **keyring_options), server_name:, keylog:, now:,
      session:, early_data:)
  end

  # A server whose Config takes 0-RTT gets an anti-replay record of its own
  # unless one is given, open from the start.
  def server(config: TLSPair.server_config, keyring: nil, anti_replay: nil, now: NOW)
    anti_replay ||= TLS::AntiReplay::Memory.new(now:, warmup: false) if config.max_early_data_size.positive?
    TLS::TCP::Connection.server(config:, keyring: keyring || TLSPair.server_keyring(config:), now:, anti_replay:)
  end

  # A client and a server, run until neither has more to send.
  def connect(client: self.client, server: self.server)
    pump(client, server)
    Pair.new(client:, server:)
  end

  # Moves bytes both ways until neither side has any left.
  def pump(a, b)
    loop do
      moved = false
      a.each_output { |bytes| b.receive(bytes, now: NOW).then { moved = true } }
      b.each_output { |bytes| a.receive(bytes, now: NOW).then { moved = true } }
      break unless moved
    end
  end

  # Every byte `connection` has to send.
  def take(connection)
    taken = "".b
    connection.each_output { |bytes| taken << bytes }
    taken
  end

  def events(connection)
    [].tap { |list| while (event = connection.next_event) do list << event end }
  end

  # [content type, length] of each record in `bytes`.
  def records(bytes)
    offset = 0
    list = []
    while offset < bytes.bytesize
      type, length = bytes.byteslice(offset, 5).to_s.unpack("Cx2n")
      list << [type, length]
      offset += 5 + length.to_i
    end
    list
  end
end
