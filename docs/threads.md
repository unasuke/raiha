# Threads

`Raiha::Runtime::Threaded` is the runtime of [Fiber scheduler](fiber-scheduler.md) on threads. It has the same classes by the same names, `Server`, `Client`, `Session`, `Stream`, `HTTP3::Server` and `HTTP3::Client`, with the same methods, and needs no scheduler gem: call it from any thread. Where the runtime of fibers starts a fiber, this one starts a thread: one for each connection's handler, each stream of `each_stream` and each HTTP/3 request.

Use it when a handler calls a library that blocks its whole thread, such as a C extension that does not cooperate with a Fiber scheduler. Under the runtime of fibers, such a call holds up every connection of that thread; here it holds up only its own. It is not faster: Ruby's GVL still runs one thread's Ruby code at a time.

## Choosing the runtime

Use the namespace directly, or let `Raiha::Runtime.for` give it:

```ruby
runtime = Raiha::Runtime.for(concurrency: :thread) # => Raiha::Runtime::Threaded
runtime::HTTP3::Server.new(config: Raiha::QUIC::Config.new, tls_config: tls, keyring:, port: 4433)

Raiha::Runtime.for # => Raiha::Runtime, the runtime of fibers
```

`concurrency:` is `:fiber` (the default) or `:thread`; anything else raises `ArgumentError`.

## HTTP/3 server

```ruby
require "raiha"

registry = Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension)
tls = Raiha::TLS::Config.server(profile: Raiha::TLS::Profile::QUIC, alpn: ["h3"], registry:)
identity = Raiha::TLS::Keyring::Identity.new(
  cert_der: OpenSSL::X509::Certificate.load(File.read("fullchain.pem")).map(&:to_der),
  key_der: OpenSSL::PKey.read(File.read("privkey.pem")).private_to_der
)
keyring = Raiha::TLS::Keyring.server(config: tls, identities: [identity])

server = Raiha::Runtime::Threaded::HTTP3::Server.new(config: Raiha::QUIC::Config.new, tls_config: tls, keyring:, host: "::", port: 4433)
trap("INT") { server.stop }

server.run do |request|
  request.respond(200, [["content-type", "text/plain"]], "hello from #{request.path}\n")
end
```

There is no `Sync`: `run` blocks the thread that calls it until the server stops. Each request runs in a thread of its own, so the block may block.

`Threaded::HTTP3::Server.new` and `Threaded::Server.new` take the keywords of the runtime of fibers (see [Server options](fiber-scheduler.md#server-options)), except that there is no `worker:`, and with these defaults and one more:

| Keyword | Default | Meaning |
| --- | --- | --- |
| `max_connections:` | `64` | The most connections at a time, counting the handlers that have not ended (see [How many threads](#how-many-threads)). The runtime of fibers takes 1024. |
| `max_threads:` | `256` | The most threads of streams and requests at a time. An Integer of 1 or more. |

Requests, responses, `stop`, `reconfigure` and 0-RTT work as [the HTTP/3 server of fibers](fiber-scheduler.md#http3-server) does.

## HTTP/3 client

```ruby
require "raiha"

registry = Raiha::TLS::Extension::Registry::BUILTIN.with(Raiha::QUIC::TransportParameters::Extension)
tls = Raiha::TLS::Config.client(trust_anchors: [File.read("ca.der")], profile: Raiha::TLS::Profile::QUIC, alpn: [Raiha::Runtime::Threaded::HTTP3::Client::ALPN], registry:)
keyring = Raiha::TLS::Keyring.client(config: tls)

response = Raiha::Runtime::Threaded::Client.connect("localhost", 4433, config: Raiha::QUIC::Config.new, tls_config: tls, keyring:) do |session|
  Raiha::Runtime::Threaded::HTTP3::Client.new(session).get("/")
end
puts response.status, response.body
```

`Threaded::Client.connect` takes the keywords of [the client of fibers](fiber-scheduler.md#connecting), and `max_threads:` (default 64), the most threads of the streams of `each_stream` at a time. The block runs in the thread that called `connect`.

One `Threaded::HTTP3::Client`, or one `Threaded::Session`, may be used from several threads at once: each request, or each stream, goes on a stream of its own.

```ruby
Raiha::Runtime::Threaded::Client.connect("localhost", 4433, config: Raiha::QUIC::Config.new, tls_config: tls, keyring:) do |session|
  client = Raiha::Runtime::Threaded::HTTP3::Client.new(session)
  %w[/a /b /c].map { |path| Thread.new { client.get(path).body } }.map(&:value)
end
```

Two threads must not read one `Stream`, or write one, at the same time.

## QUIC

`Threaded::Server#run` gives the block each `Threaded::Session`, and `Threaded::Client.connect` gives its block one, as [the runtime of fibers](fiber-scheduler.md#quic) does. `each_stream` runs each stream in a thread of its own. The methods of `Session` and `Stream` are those of [Session](fiber-scheduler.md#session) and [Streams](fiber-scheduler.md#streams).

`session.connection` is the `QUIC::Connection` behind a lock: each of its methods takes the runtime's lock for the call, so `session.connection.stream_reset(stream.id, error_code: 7)` followed by `session.changed` works from any thread, as it does under the runtime of fibers. What a call returns, `session.connection.stats` for one, is read without the lock and may change while you read it.

## How many threads

| Thread | How many |
| --- | --- |
| A socket's reader (`raiha-reader`) | One for each socket of a server or a client |
| The runner (`raiha-runner`) | One for each server, and for each connection of a client |
| The one that waits for `stop` (`raiha-wake`) | One for each server |
| A connection's handler (`raiha-conn`) | One for each connection, `max_connections` at most |
| A stream of `each_stream` (`raiha-stream`) | One for each stream, within `max_threads` |
| An HTTP/3 request (`raiha-request`) | One for each request, within `max_threads` |

A server starts at most `max_connections + max_threads` threads for the application, 320 by default. A handler counts toward `max_connections` until its thread ends, even after its connection has closed: a handler held up in a library keeps its place, and once `max_connections` places are taken, new connections are refused with CONNECTION_REFUSED. When `max_threads` threads of streams and requests are running, the next stream or request waits for one to end; its data waits in QUIC's flow control, and beyond that the peer waits. Threads the application starts itself are not counted.

The places are limited, so a request whose handler waits for the answer to another request to the same server can deadlock: if every place is taken by such handlers, the requests they wait for never get a thread.

## Stopping

`stop` writes to a pipe and takes no lock, so a signal handler may call it, as under the runtime of fibers. The sessions are told they are `stopping?` and have the `timeout` to end their connections; those left are closed.

`run` then waits for the threads it started to end, until the time `stop` gave, or for `Threaded::Server::STOP_TIMEOUT` (30 seconds) when `run` is left by an exception such as `Interrupt`. A thread still running after that, held up in a library say, is not killed: `run` returns and leaves it running. Its connection has closed, so what it calls of the connection raises `Raiha::QUIC::ClosedError`. `Threaded::Client.connect` likewise waits for the threads of `each_stream` for `STOP_TIMEOUT` once its block is over.

## Cancellation

No thread is interrupted with `Thread#raise`, which could stop it anywhere, in an `ensure` or with the runtime's lock held. When a server runs out of time to stop, it cancels the requests left with `H3_REQUEST_CANCELLED`; a thread that waits in a read or a write of its request raises `Raiha::Runtime::HTTP3::StreamReset` there, and one held up elsewhere raises it the next time it reads or writes. The runtime of fibers interrupts a fiber where it waits, when the scheduler can.

## Exceptions

When a handler raises, its connection is closed with `INTERNAL_ERROR`, or its request answered with 500 or reset with `H3_INTERNAL_ERROR`, as under the runtime of fibers. The exception ends its thread, and Ruby reports it on standard error (`Thread#report_on_exception`).

## The lock

Each server and client has one lock, a `Monitor`, that every thread takes before it touches a connection or HTTP/3: the methods of `Session`, `Stream` and `HTTP3` take it and let it go while they wait. No I/O and no code of the application runs under it.

A protocol over a `Session`, such as one of your own beside HTTP/3, is called under the lock: its `take` and `turn`, and the blocks of `session.wait_for`. They must not wait for anything, or every connection of the server waits with them. Code of the application called with the lock held raises `Raiha::Runtime::Error::Usage`, as `session.each_stream` called inside the block of `session.wait_for` does.

The two runtimes do not mix within a connection: `Threaded::HTTP3::Client.new` raises `Error::Usage` given a `Session` of the runtime of fibers, and `Raiha::Runtime::HTTP3::Client.new` given a `Threaded::Session`. A server of one and a client of the other speak QUIC to each other as usual.

## Limits

- There is no Rack adapter and no `Workers` for the runtime on threads.
- It may be called inside a Fiber scheduler, from `Sync` say, and in a Ractor other than the main one, but neither is tested. A Ractor other than the main one runs its threads on Ruby's M:N scheduler, where OpenBSD with Ruby 4.0 has a bug that can crash the process (see [Workers and SO_REUSEPORT](platforms.md#workers-and-so_reuseport)).
- The qlog files are written as under the runtime of fibers (see [qlog.md](qlog.md)). The traces of the runtime on threads draw on a budget of their own, apart from that of the runtime of fibers in the same Ractor.
