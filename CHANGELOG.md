# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- QUIC version 1 (RFC 9000, RFC 9001, RFC 9002): streams, DATAGRAM frames (RFC 9221), 0-RTT and resumption, Retry, connection migration and preferred addresses, path MTU discovery, ECN, NewReno and CUBIC
- HTTP/3 (RFC 9114) with QPACK (RFC 9204) and extensible priorities (RFC 9218)
- TLS 1.3, for QUIC and over TCP
- A sans-I/O core: the protocols do no I/O, and you drive them from your own socket loop
- `Raiha::Runtime`, a runtime that serves and connects over UDP sockets under a Fiber scheduler, with Ractor workers (`Raiha::Runtime::Workers`), a Rack 3 adapter (`Raiha::Runtime::Rack`) and qlog
- `Raiha::Runtime::Threaded`, a runtime on threads that needs no Fiber scheduler
- RBS signatures under `sig/`
- Documentation under `docs/` and examples under `examples/`

### Changed

- Require Ruby 4.0 or later and the `openssl` gem 4.0 or later
- License under the Apache License 2.0

## [0.1.0] - 2021-08-04

### Added

- The skeleton of the gem, with nothing implemented

[Unreleased]: https://github.com/unasuke/raiha/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/unasuke/raiha/releases/tag/v0.1.0
