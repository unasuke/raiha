require "raiha/next/quic/test"
require "raiha/next/tls/test"
require "raiha/next/support/quic_pair"

# Everything a handshake on a Test::Network takes, fixed, so that the bytes
# of its datagrams are the same on every run: certificates of fixed Ed25519
# keys and times, whose signatures are deterministic, key shares of fixed
# private keys, random bytes from fixed seeds and a fixed wall clock.
module NextQUICGolden
  include NextQUICPair

  PKI = NextTestPKI
  TIME = Time.utc(2026, 1, 1)
  VALIDITY = { not_before: TIME - 86_400, not_after: TIME + 86_400 * 3650 }.freeze

  CA = PKI.issue(subject: "Golden CA", key: OpenSSL::PKey.new_raw_private_key("ED25519", "\x01".b * 32), issuer: nil, ca: true, **VALIDITY)
  LEAF = PKI.issue(subject: "leaf", key: OpenSSL::PKey.new_raw_private_key("ED25519", "\x02".b * 32), issuer: CA, ca: false,
    names: ["DNS:localhost"], purpose: "serverAuth", serial: 2, **VALIDITY)

  # A path model that passes everything on at once and keeps, for each
  # datagram, the time, the source and the payload.
  class Recorder
    attr_reader :log

    def initialize
      @log = []
      @queue = []
    end

    def start(random:) = self

    def submit(datagram, now:)
      @log << [now, datagram.source, datagram.payload]
      @queue << datagram
    end

    def each_delivery(now:)
      queue = @queue
      @queue = []
      queue.each { yield _1 }
    end

    def next_timeout = nil
  end

  module_function

  def tls_config(role)
    TLS::Config.public_send(role, trust_anchors: [CA.der], profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY, groups: [:x25519])
  end

  # A client and a server on a network of `seed`, linked by `recorder`,
  # which keeps every datagram either sends, and then `model`.
  def network(seed:, recorder:, model: [])
    net = QUIC::Test::Network.new(seed:)
    client_tls = tls_config(:client)
    client_keyring = TLS::Keyring.client(config: client_tls, random: Random.new(seed + 1),
      key_exchange: TLS::Test::FixedKEM.new({ x25519: "\x03".b * 32 }))
    client = net.add(QUIC::Connection.client(config: QUIC::Config.new, tls_config: client_tls, keyring: client_keyring,
      server_name: "localhost", remote: SERVER, time: TIME, now: 0.0), address: CLIENT)
    server_tls = tls_config(:server)
    identity = TLS::Keyring::Identity.new(cert_der: [LEAF.der, CA.der], key_der: LEAF.key_der)
    server_keyring = TLS::Keyring.server(config: server_tls, identities: [identity], random: Random.new(seed + 2),
      key_exchange: TLS::Test::FixedKEM.new({ x25519: "\x04".b * 32 }))
    server = net.add_server(config: QUIC::Config.new, tls_config: server_tls, keyring: server_keyring, time: TIME, address: SERVER)
    net.link(client, server, model: [recorder, *model])
    [net, client, server]
  end
end
