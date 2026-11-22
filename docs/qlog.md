# qlog

Raiha writes [qlog](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/) traces of its QUIC connections, and of HTTP/3 over them, so that a connection can be looked at after the fact with qvis or another qlog tool. The runtime writes one file per connection into a directory you name; the sans-I/O layers take a tracer object of your own instead.

## Turning it on in the runtime

`Raiha::Runtime::Server`, `Raiha::Runtime::HTTP3::Server` and `Raiha::Runtime::Client.connect` take `qlog_dir:`. Without it (the default, `nil`) nothing is traced. The directory is created if it is not there.

```ruby
server = Raiha::Runtime::HTTP3::Server.new(config:, tls_config:, keyring:, host: "::", port: 443, qlog_dir: "log/qlog")

Raiha::Runtime::Client.connect("example.com", 443, config:, tls_config:, keyring:, qlog_dir: "log/qlog") do |session|
  # ...
end
```

The servers of `Raiha::Runtime::Workers` are made in the block each worker runs, so pass `qlog_dir:` there; every worker may share one directory. See [fiber-scheduler.md](fiber-scheduler.md) for the rest of their arguments, and `examples/qlog_output.rb` and `examples/qlog_roundtrips.rb` for complete programs.

### File names

- A server's trace is `<connection ID>_server.sqlog`, named by the Destination Connection ID the client first chose, in hex.
- A client's trace is `<time>_client.sqlog`, named by the UTC time the connection was tried, as `%Y%m%dT%H%M%S.%6N` (for example `20261116T112340.256879_client.sqlog`). Each address `Client.connect` tries has a trace of its own.

Files are created readable by their owner only (mode 0600), as they hold what the peers said. A file is opened without following symbolic links and used only when it is a regular file, and it is held under an exclusive `flock` while its trace writes; a trace whose file cannot be had so is dropped.

### Limits

A busy server must not fill its disk with qlog, so the runtime bounds what it writes:

| Limit | Size | What happens |
| --- | --- | --- |
| One trace | 64 MiB (`Raiha::QUIC::Qlog::Tracer::DEFAULT_MAX_BYTES`) | The trace ends with a `raiha:qlog_stopped` event naming the limit. |
| All traces of one Ractor | 1 GiB (`Raiha::Runtime::Qlog::BUDGET`) | Spent bytes never come back: once the budget is gone, every trace of that Ractor stops, and traces begun later write nothing until the process restarts. Each worker of `Workers` has its own budget. |
| The directory | 1 GiB and 4,096 files (`Raiha::Runtime::Qlog::MAX_FILES`) | Before a new trace begins, the oldest `.sqlog` files no trace is writing are deleted, files from earlier runs included. |

The directory is listed once, when the server or client is made; after that it counts only the files it has closed itself. A file another process holds the lock of is neither deleted nor counted.

Traces are written to memory first, since a call into the protocol core never waits on I/O, and go to their files after each turn of the runtime's driver.

## What is in a trace

Each file is a JSON Text Sequence (RFC 7464): records separated by the byte `0x1e`, each followed by a line feed. The first record is the header:

- `file_schema` is `urn:ietf:params:qlog:file:sequential` and `serialization_format` is `application/qlog+json-seq`. The header also carries `qlog_version` `"0.3"` and `qlog_format` `"JSON-SEQ"` of the earlier drafts, which qvis looks for.
- `event_schemas` lists `urn:ietf:params:qlog:events:quic` (the events follow draft-ietf-quic-qlog-main-schema-13 and quic-events-12), and also `urn:ietf:params:qlog:events:http3-12` (draft-ietf-quic-qlog-h3-events-12) when the ALPN of the TLS config includes `h3`.
- Times are milliseconds of the monotonic clock the connection is given; the reference time's epoch is `unknown`.

QUIC events:

- `quic:packet_sent`, `quic:packet_received` (with the frames of each packet), `quic:packet_dropped`, `quic:packet_lost`
- `quic:parameters_set`, `quic:recovery_parameters_set`, `quic:recovery_metrics_updated`, `quic:congestion_state_updated`, `quic:timer_updated`
- `quic:ecn_state_updated`, `quic:mtu_updated`, `quic:connection_id_updated`, `quic:migration_state_updated`, `quic:key_updated`
- `quic:connection_data_blocked_updated`, `quic:stream_data_blocked_updated`

HTTP/3 events: `http3:parameters_set`, `http3:stream_type_set`, `http3:frame_created`, `http3:frame_parsed`, `http3:priority_updated`.

Events qlog has no name for are under `raiha:`: `raiha:spurious_loss`, the traces of the TLS handshake as `raiha:tls_<name>` (for example `raiha:tls_transcript_updated`), and `raiha:qlog_stopped`.

What a trace leaves out:

- Stream and datagram payloads appear only as their length; connection IDs and other bytes are hex. The data of PATH_CHALLENGE and PATH_RESPONSE is written in full.
- No key is written, a key update included.
- In HTTP/3 field sections, a name or value is cut to 256 bytes and a section to 64 lines, the rest counted. The values of `authorization`, `proxy-authorization`, `cookie` and `set-cookie` are written as their length only. A name or value that is not printable text is written in hex.

## Opening the files

[qvis](https://qvis.quictools.info/) opens `.sqlog` files directly: load them through its file picker. Since each record is one line of JSON after the `0x1e` separator, the files can also be read with ordinary tools, for example:

```sh
tr -d '\036' < log/qlog/c93f63f45e397579_server.sqlog | jq -c 'select(.name == "quic:packet_lost")'
```

## Tracers in the sans-I/O layers

Below the runtime, the protocol layers do no I/O and write nothing themselves; they call a tracer you pass.

- `Raiha::QUIC::Tracer` is the interface of a QUIC connection's tracer: one method per qlog event (`packet_sent`, `packet_lost`, `metrics_updated`, and so on). Every method is optional; include the module and override the ones you want. `Raiha::QUIC::Connection.client` / `.server` and `Raiha::QUIC::Endpoint#connect` / `#accept` take it as `tracer:`. Without a tracer, not even the arguments of an event are built.
- `Raiha::QUIC::Qlog::Tracer.new(io, vantage_point:, title: nil, max_bytes: 64 MiB, budget: nil, event_schemas: [])` is the tracer the runtime uses: it writes JSON-SEQ to any `io` that answers `write`. `vantage_point` is `:client` or `:server`; `budget` is a `Raiha::QUIC::Qlog::Budget.new(max_bytes:)` shared by several traces.
- `Raiha::HTTP3::Tracer` is the interface of an HTTP/3 connection's tracer, taken by `Raiha::HTTP3::Connection.client` / `.server` as `tracer:`. `Raiha::HTTP3::Qlog::Tracer.new(quic_tracer)` writes the HTTP/3 events into the same file as the QUIC qlog tracer of that connection, through its `record(name, data)`; name the HTTP/3 schema in that tracer's `event_schemas` (`Raiha::HTTP3::Qlog::EVENT_SCHEMA`).

## TLS secrets

To decrypt a packet capture in Wireshark, the TLS traffic secrets can be written in the SSLKEYLOGFILE format (RFC 9850). Nothing writes them unless code asks: the environment variable `SSLKEYLOGFILE` is not read by the library, and the runtime's `Server` and `Client` take no keylog. At the sans-I/O level, `Raiha::QUIC::Endpoint#connect` / `#accept` and `Raiha::QUIC::Connection.client` / `.server` take `keylog:`, anything that answers `write(line)`, such as `Raiha::TLS::Keylog::File.new(path)` (opened for appending, mode 0600). Only the traffic secrets are written, not the exporter secret. RFC 9850 forbids this in production.

The quic-interop-runner endpoint under `interop/` writes a keylog when `SSLKEYLOGFILE` is set, and qlog into `QLOGDIR`; see [interop/README.md](../interop/README.md).
