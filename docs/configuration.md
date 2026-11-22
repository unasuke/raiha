# Configuration

A connection is set up from three objects:

- `Raiha::QUIC::Config` holds the transport parameters this end sends, and settings of this implementation that never go on the wire. It is frozen and can be shared between Ractors.
- `Raiha::TLS::Config` holds the TLS settings: ALPN, cipher suites, trust anchors, session tickets and 0-RTT. It is also frozen and shareable. Build one with `TLS::Config.server` or `TLS::Config.client`.
- `Raiha::TLS::Keyring` holds what cannot be shared: certificates and private keys, the trust store, and the random source. Build one per process or Ractor, not per connection, since it parses its certificates once.

A setting that cannot work raises `ArgumentError` when the object is built, not later during a handshake.

```ruby
registry = Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension)

server_tls = Raiha::TLS::Config.server(profile: Raiha::TLS::Profile::QUIC, alpn: ["echo"], registry:)
server_keyring = Raiha::TLS::Keyring.server(config: server_tls, identities: [identity])

client_tls = Raiha::TLS::Config.client(profile: Raiha::TLS::Profile::QUIC, alpn: ["echo"], registry:, trust_anchors: [ca_der])
client_keyring = Raiha::TLS::Keyring.client(config: client_tls)

quic = Raiha::QUIC::Config.new(max_idle_timeout: 10.0)
```

## TLS for QUIC

QUIC needs two settings that TLS over TCP does not:

- `profile: TLS::Profile::QUIC`. The default is `TLS::Profile::TCP`, and a connection whose TLS config has another profile raises `ArgumentError` ("the TLS Config of a QUIC connection has the QUIC profile"). The profile gathers what RFC 9001 changes in TLS: handshake messages travel in CRYPTO frames, middlebox compatibility mode and EndOfEarlyData are dropped, a KeyUpdate message is an error, and ALPN must be agreed.
- `registry: TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)`. This registers the `quic_transport_parameters` extension with the TLS layer, so TLS refuses the extension in any message other than ClientHello and EncryptedExtensions. Without it a handshake still completes, because the TLS layer passes the extension's bytes through untouched, but that check is skipped. The QUIC layer decodes the parameters either way.

`alpn` is required in practice: QUIC endpoints must agree on a protocol, and the handshake fails with `no_application_protocol` if they do not. HTTP/3 uses `"h3"` (`Raiha::Runtime::HTTP3::Client::ALPN`).

## Certificates and keys

A `TLS::Keyring::Identity` is a certificate chain, leaf first, as an Array of DER Strings, together with the leaf's private key in DER or PEM. A server needs at least one identity. The keyring checks that each key matches its certificate.

```ruby
require "openssl"

# fullchain.pem holds the leaf certificate followed by its intermediates.
chain = OpenSSL::X509::Certificate.load(File.read("fullchain.pem")).map(&:to_der)
key = OpenSSL::PKey.read(File.read("server.key")).private_to_der
identity = Raiha::TLS::Keyring::Identity.new(cert_der: chain, key_der: key)

keyring = Raiha::TLS::Keyring.server(config: server_tls, identities: [identity])
```

`OpenSSL::X509::Certificate.load` reads every certificate in the file; `OpenSSL::X509::Certificate.new` would read only the first.

With several identities, the server picks for each handshake an identity whose key can sign with a scheme the client offers. Among those, it prefers one valid for the requested server name, then one whose whole chain the client accepts, then one issued by a CA the client names. Ties go to the order of `identities`.

### Trust anchors

A client verifies the server against `trust_anchors:`, an Array of DER certificates in its `TLS::Config`. To trust the system's store, read all of its certificates:

```ruby
trust_anchors = OpenSSL::X509::Certificate.load(File.read(OpenSSL::X509::DEFAULT_CERT_FILE)).map(&:to_der)
```

A client keyring built without trust anchors raises `ArgumentError` ("the default verifier needs trust_anchors in the Config (or pass verifier:)"). `TLS::Verifier::None.new` accepts any chain and is for tests only: a keyring built with it answers `peer_verified?` with `false`.

### Client certificates

A server asks for client certificates with `client_auth: :optional` or `:required`, and needs `trust_anchors` to verify them. A client gives its own with `TLS::Keyring.client(config:, identities: [...])`. It sends the first identity whose key signs with a scheme the server lists and, when the server names CAs, whose chain has an issuer among them.

## `TLS::Config` settings

`TLS::Config.server(**options)` and `TLS::Config.client(**options)` take the same keywords. Some are only for one role; giving one to the other role raises `ArgumentError`. `config.with(...)` returns a copy with some settings changed.

| Setting | Default | Meaning |
| --- | --- | --- |
| `profile` | `TLS::Profile::TCP` | `TLS::Profile::QUIC` for QUIC. |
| `alpn` | `[]` | The ALPN protocol names, in order of preference. |
| `registry` | `Extension::Registry::BUILTIN` | The extensions TLS can parse. See above. |
| `cipher_suites` | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | Symbols such as `:TLS_AES_128_GCM_SHA256`. |
| `groups` | `x25519`, `secp256r1`, `secp384r1` | Key exchange groups. |
| `signature_algorithms` | ECDSA P-256, RSA-PSS, Ed25519, ... | Schemes for CertificateVerify, in order of preference. |
| `signature_algorithms_cert` | the above plus RSA PKCS#1 and ECDSA P-521 | Schemes accepted in certificate chains. |
| `trust_anchors` | `[]` | DER certificates to verify the peer against. |
| `verify_flags` | `0` | Flags for `OpenSSL::X509::Store`. |
| `client_auth` | `:none` | Server only: `:none`, `:optional` or `:required`. |
| `require_server_name` | `false` | Server only: refuse a ClientHello without SNI. |
| `resumption` | `true` | Client only: whether to resume with a ticket it is given. |
| `ticket_keys` / `ticket_key` | `nil` | Server only: the keys that seal session tickets. See below. |
| `ticket_lifetime` | `7200` | Seconds a ticket lives, at most 604800. |
| `ticket_count` | `2` with keys, else `0` | Server only: tickets issued per connection. |
| `max_early_data_size` | `0` | Server only: more than 0 allows 0-RTT. With the QUIC profile, any positive value becomes `0xffffffff`, as RFC 9001 asks. |
| `resumption_scope` | `""` | Server only: bound into tickets, so that a ticket of another scope does not resume. |
| `grease`, `permute_extensions` | `true`, `true` | GREASE values and a shuffled extension order in the ClientHello. |

The rest (`extensions`, `exporter_labels`, `record_size_limit`, `certificate_authorities`, `max_ticket_size` and the message size limits) are documented in [lib/raiha/tls/config.rb](../lib/raiha/tls/config.rb).

## Tickets and 0-RTT

A server issues session tickets only when it has keys to seal them, and takes 0-RTT only then:

```ruby
server_tls = Raiha::TLS::Config.server(
  profile: Raiha::TLS::Profile::QUIC,
  alpn: ["echo"],
  registry:,
  ticket_keys: Raiha::TLS::TicketKeys.static(current: SecureRandom.bytes(32)),
  max_early_data_size: 1 # any positive value allows 0-RTT
)
```

`max_early_data_size` without ticket keys raises `ArgumentError`. `ticket_key: seed` is short for `ticket_keys: TLS::TicketKeys.static(current: seed)`. Each seed is 32 bytes.

There are two kinds of ticket keys.

- `TLS::TicketKeys.static(current:, previous: [])` seals with `current` and opens tickets sealed with `current` or any of `previous`. To turn the keys over, build a new `TLS::Config` and `TLS::Keyring` and hand them to `Server#reconfigure`.
- `TLS::TicketKeys.ratchet(base:, base_epoch:, origin:, now:, epoch: 3600, retain: nil, horizon: 24)` gives each `epoch` seconds of the wall clock since `origin` a key of its own. Each epoch's seed is derived from the one before. Servers given the same `base`, `base_epoch`, `origin` and `epoch` compute the same keys without talking to each other. A `Runtime::Server` moves to the next epoch's keys by itself. `base` is the seed of epoch `base_epoch`, which must be no later than the first epoch kept: the current epoch less `retain`, where `retain` defaults to the ticket lifetime in epochs plus one. A base too far behind (more than 4096 epochs) is refused; hand out the `base` and `base_epoch` of `keys.advance(now:)` instead.

```ruby
origin = Time.utc(2026, 1, 1)
now = Time.now
keys = Raiha::TLS::TicketKeys.ratchet(base: seed, base_epoch: ((now - origin) / 3600).floor - 24, origin:, now:)
```

In the runtime, a client resumes by passing a ticket from `Session#tickets` to `Client.connect(session:)`, and sends 0-RTT with `early_data: true`; see [fiber-scheduler.md](fiber-scheduler.md#resuming-a-connection). In the sans-I/O core, tickets come as `Raiha::QUIC::Event::SessionTicket` and go to `Raiha::QUIC::Connection.client(session:)` or `Raiha::QUIC::Endpoint#connect(session:)`; see [quic.md](quic.md#resumption-and-0-rtt) and, for HTTP/3, [http3-client.md](http3-client.md#several-requests-resumption-and-0-rtt).

### Replay protection

An attacker can replay 0-RTT. A server records the ClientHello of each 0-RTT it takes, in its `anti_replay:`, so that it takes each at most once. By default, `Runtime::Server` makes a `TLS::AntiReplay::Memory.new(now: Time.now)`. For its first 11 seconds, that record takes no 0-RTT, so a ClientHello taken before a restart is not taken again. `TLS::AntiReplay::Memory.new(now:, warmup: false)` skips the warm-up. That is safe only when every ticket key is newer than the record, as with keys made at random at start-up.

Servers in other processes that open the same tickets keep separate records, so each of them may take a ClientHello's 0-RTT once. `Runtime::Workers` gives its Ractors one shared record.

`app_early_data_context:` on `Runtime::Server` names what your 0-RTT depends on, such as the application's settings. A ticket issued under another context has its 0-RTT rejected. The connection still resumes.

## `QUIC::Config` settings

`QUIC::Config.new(**options)` takes these keywords; `config.with(...)` returns a copy with some changed. Times are Float seconds, sizes are bytes. `inspect` masks the two keys.

### Transport parameters

These are sent to the peer, named as RFC 9000 names them.

| Setting | Default | Meaning |
| --- | --- | --- |
| `max_idle_timeout` | `30.0` | Seconds of silence before the connection closes. |
| `max_udp_payload_size` | `65527` | The largest UDP payload this end can receive. |
| `initial_max_data` | `768 KiB` | The connection's initial flow control window. |
| `initial_max_stream_data_bidi_local` | `512 KiB` | The initial window of a bidirectional stream this end opened. |
| `initial_max_stream_data_bidi_remote` | `512 KiB` | The initial window of a bidirectional stream the peer opened. |
| `initial_max_stream_data_uni` | `512 KiB` | The initial window of a unidirectional stream the peer opened. |
| `initial_max_streams_bidi` | `100` | How many bidirectional streams the peer may open. |
| `initial_max_streams_uni` | `100` | How many unidirectional streams the peer may open. HTTP/3 needs three. |
| `max_ack_delay` | `0.025` | The longest this end delays an acknowledgement. |
| `ack_delay_exponent` | `3` | The exponent of the ACK Delay field. |
| `active_connection_id_limit` | `8` | How many of the peer's connection IDs this end keeps. |
| `disable_active_migration` | `false` | Tells the peer not to migrate. |
| `max_datagram_frame_size` | `nil` | `nil` or `0` for no DATAGRAM frames; RFC 9221 suggests `65535` to have them. |

### This implementation

| Setting | Default | Meaning |
| --- | --- | --- |
| `versions` | `[QUIC::Version::V1]` | The QUIC versions spoken. Only version 1 is supported. |
| `connection_id_length` | `8` | Bytes of the connection IDs this end issues, 0 to 20. |
| `initial_max_datagram_size` | `1200` | The datagram size before a path is probed. At least 1200. |
| `enable_pmtud` | `true` | Probe each path for larger datagrams (RFC 8899). |
| `max_stream_receive_window` | `6 MiB` | How far a stream's receive window can grow. |
| `max_receive_window` | `15 MiB` | How far the connection's receive window can grow. |
| `max_send_buffer` | `15 MiB` | The most unacknowledged data kept for sending. |
| `congestion_control` | `QUIC::Congestion::Cubic` | `:cubic`, `:new_reno`, or a class of your own. |
| `initial_window` | `min(10 × size, max(14720, 2 × size))` | A lambda from the datagram size to the initial window, as RFC 9002 gives it. Make your own with `Ractor.shareable_lambda`. |
| `startup` | `nil` | A class that wraps the controller while the connection starts, such as `QUIC::Congestion::Startup::RapidStart`. `nil` keeps the controller's own slow start. |
| `pacing_granularity` | `0.001` | Seconds between the wake-ups of pacing. |
| `max_transmit_size` | `nil` | The most bytes one send carries, cut into datagrams of one size (but the last) for GSO. `nil` means one datagram per send. The runtime fills it in; see below. |
| `fast_convergence` | `true` | CUBIC's fast convergence (RFC 9438). |
| `beta_ecn` | `nil` | The factor the window is multiplied by when an ECN-CE mark alone starts recovery. `nil` uses the algorithm's own loss factor. |
| `retry_token_key` | `nil` | The secret Retry tokens are made with, 32 bytes at least. |
| `stateless_reset_key` | `nil` | The secret stateless reset tokens are made with, 32 bytes at least. |
| `preferred_address` | `nil` | Server only: `{ipv4: [host, port], ipv6: [host, port]}`, either or both. Needs `connection_id_length` above 0. |
| `address_families` | `[:ipv4, :ipv6]` | The families this end can send to. A client picks the server's preferred address from these. |
| `ecn_address_families` | `[:ipv4, :ipv6]` | The families whose paths use ECN. A path of another family sends Not-ECT. |

When `retry_token_key` and `stateless_reset_key` are left `nil`, each endpoint draws its own, which only that process can use. Every process serving the same connections must be given the same keys. `Runtime::Workers` draws one pair and shares it among its Ractors.

The settings are checked against each other as well:

- Each receive window must be able to grow past its initial value: `max_stream_receive_window` at least each initial stream limit, and `max_receive_window` at least `initial_max_data` and at least 1.5 × `max_stream_receive_window`.
- The initial window must be at least two datagrams.

For example, raising `initial_max_data` alone to 32 MiB raises `ArgumentError` ("max_receive_window 15728640 is under initial_max_data").

### What the runtime changes

`Runtime::Server` and `Runtime::Client` adjust the config to their socket:

- A config without `max_transmit_size` gets `Runtime::UDP::MAX_TRANSMIT` (65507). The socket cuts each send into datagrams itself, with GSO where the OS has it.
- `enable_pmtud` is set to `false` where the socket cannot keep IP from fragmenting. Today that means everywhere but Linux.
- `:ipv4` is dropped from `ecn_address_families` where the OS has no `IP_RECVTOS`, as on OpenBSD.

See [platforms.md](platforms.md).

## Changing settings on a running server

`Runtime::Server#reconfigure(tls_config:, keyring:)` switches the TLS config and keyring for the connections that come after the call, for a renewed certificate or new static ticket keys. Connections already taken keep their own. The `QUIC::Config` cannot be changed on a running server, because its keys and connection ID length are part of the endpoint. `Runtime::Workers#reconfigure` does the same across all workers; see [fiber-scheduler.md](fiber-scheduler.md#several-ractors-with-workers).

```ruby
server.reconfigure(tls_config: server_tls, keyring: Raiha::TLS::Keyring.server(config: server_tls, identities: [renewed_identity]))
```
