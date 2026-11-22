# Development

## Setting up

You need Ruby 4.0 or later (see [platforms.md](platforms.md)). Then install the bundle:

```sh
bin/setup        # runs bundle install
```

The bundle adds, for development, `steep`, `rbs`, `rake`, `rubocop` and `debug`. For tests it adds `minitest`, `simplecov`, `async`, `rack` and `tttls1.3`:

- `async` is the Fiber scheduler the runtime's tests run under.
- `rack` provides `Rack::Lint` for the Rack adapter's tests; the adapter itself does not depend on rack.
- `tttls1.3` is a TLS 1.3 implementation in Ruby, used as an interop peer.

The optional `interop` group holds the `quic` gem, which builds native extensions at install time; see below.

## Tests

The tests use minitest and live under `test/`. `test/raiha/` holds the unit tests of each layer, and `test/interop/` the tests against other implementations.

```sh
bundle exec rake test:unit       # every test but the interop ones
bundle exec rake test:tls        # one layer: test:tls, test:quic, test:http3, test:runtime
bundle exec ruby -Ilib:test test/raiha/runtime/udp_test.rb   # one file
```

`rake test` (the default task) runs everything under `test/`, interop tests included.

## Type checking

The signatures are RBS files under `sig/`, mirroring `lib/`. Keep them in step with the code. Steep checks `lib/` against them:

```sh
bundle exec rbs collection install   # fetches the signatures of dependencies into .gem_rbs_collection/
bundle exec steep check
```

`rbs_collection.yaml` names the sources of those signatures, and `Steepfile` the standard libraries the check loads (`ipaddr`, `securerandom`, `socket`).

## Interop tests

Each interop test runs Raiha against another implementation. `rake test:interop:<name>` builds or fetches the peer first (through `rake interop:build:<name>`) and then runs the test. Peers that are cloned or fetched go under `tmp/`, which git ignores.

| Task | Peer | What it needs |
| --- | --- | --- |
| `test:interop:openssl` | TLS 1.3 with the `openssl` command | `openssl` on the PATH |
| `test:interop:picotls` | TLS 1.3 with h2o/picotls, cloned into `tmp/picotls` | git, cmake, make, OpenSSL headers, pkg-config |
| `test:interop:tttls13` | TLS 1.3 with the `tttls1.3` gem | nothing beyond the bundle |
| `test:interop:quicgo` | QUIC with quic-go, a helper in `test/support/quicgo` | Go, at the version in its `go.mod` |
| `test:interop:aioquic` | QUIC with aioquic, which uv fetches when the test runs | [uv](https://docs.astral.sh/uv/) |
| `test:interop:quic_gem` | QUIC with the `quic` gem (unasuke/quic-ruby: ngtcp2 and picotls) | autoconf, automake, libtool, pkg-config, a C compiler; the build runs `bundle config set --local with interop` |
| `test:interop:quiche_http3_client`, `test:interop:quiche_http3_server` | HTTP/3 with cloudflare/quiche's apps, cloned into `tmp/quiche` | git, Rust and cargo |
| `test:interop:h3i` | HTTP/3 conformance with quiche's h3i, through `test/support/h3i_harness` | the quiche clone above, Rust and cargo |
| `test:interop:h3spec` | HTTP/3 conformance with h3spec v0.1.14, downloaded into `tmp/h3spec` and checked against its SHA-256 | curl; x86_64 Linux or arm64 macOS, the only binaries the release has |
| `test:qifs` | QPACK against the qifs corpus at a fixed commit, fetched into `tmp/qifs`; the encoding test compares with ls-qpack through pylsqpack | git, uv |

`rake interop:build` builds every peer at once. `rake test:interop` runs all the interop tests without building anything first.

The aioquic and qifs encoding tests skip themselves when uv is not found.

## quic-interop-runner

`interop/` packages Raiha as an endpoint for [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner). It holds:

- a Docker image, with `run_endpoint.sh` and a dispatcher that reads the runner's environment variables;
- a compose file for running without the ns-3 simulator;
- `run_interop_runner.sh`.

How to build the image, run a local smoke test, and run the runner with or without the simulator is in [interop/README.md](../interop/README.md). That file also lists the testcases supported and the environment variables.

## Examples

`examples/` holds small programs, each runnable with `bundle exec ruby -Ilib examples/<file>.rb`. All but two run on the loopback interface with a certificate made by `examples/_certificate.rb`:

- `in_memory_handshake.rb`: a QUIC handshake between a client and a server `Raiha::QUIC::Connection` in one process, with no socket. The datagrams are handed over by hand.
- `stream_echo.rb`: the same setup, with 256 bytes echoed on a stream.
- `udp_handshake.rb`: a QUIC handshake over UDP, with the loop an application writes around a connection itself. The server is an `Endpoint` in a thread.
- `high_level_loopback.rb`: `Raiha::Runtime::Server` and `Raiha::Runtime::Client` under the `async` scheduler, echoing a stream.
- `qlog_output.rb`: the same, with each side writing a qlog to `tmp/raiha-example-qlog` (see [qlog.md](qlog.md)).
- `qlog_roundtrips.rb`: one connection with many echoes (20, or `ROUNDTRIPS`), for a richer qlog in `tmp/raiha-example-qlog-roundtrips`.
- `http3_get_public.rb`: HTTP/3 GETs to public servers, or to the URLs given, verified against the system's trust store. It needs the network.
- `quic_gem_loopback.rb`: a client of the `quic` gem, in a process of its own, against the runtime's server. It needs the `interop` bundle group.

`test/raiha/examples_test.rb` runs the six loopback and in-memory examples in `rake test:unit`. Each must print the "Expected output:" of its header comment, so keep that comment in step when changing an example. The two that need the network or the `interop` group are run by hand.

## CI

`.github/workflows/ci.yml` runs on Ruby 4.0, with one job each:

- `unit`: `rake test:unit`.
- `steep`: `rbs collection install` and `steep check`.
- One job per interop peer, which installs that peer's toolchain and runs its task: `interop-openssl`, `interop-picotls`, `interop-quicgo`, `interop-aioquic`, `interop-quic-gem`, `interop-h3i`, `interop-quiche-http3` and `interop-h3spec`.
  - The quiche jobs clone the head of cloudflare/quiche each time.
- `qifs`: `rake test:qifs`.
- `interop-runner`: builds the Docker image and runs quic-interop-runner with Raiha as both client and server.
  - The testcases are handshake, transfer, multiplexing, retry, chacha20, keyupdate, http3, resumption and zerortt.
  - Every one of them must succeed, and the logs are kept as an artifact.
