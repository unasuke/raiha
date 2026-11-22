# Platforms

Raiha is pure Ruby. It needs:

- Ruby 4.0 or later.
- The `openssl` gem 4.0 or later, which the gemspec depends on, built against OpenSSL or LibreSSL. Raiha implements TLS 1.3 itself and takes only primitives from it: AEAD ciphers, HKDF and HMAC, X25519 and ECDH, signatures, and X.509 parsing.

The protocol layers (`Raiha::TLS`, `Raiha::QUIC`, `Raiha::HTTP3`) do no I/O and run anywhere Ruby does. Everything below is about `Raiha::Runtime`, whose UDP sockets differ by operating system. It is written for Linux, and runs on OpenBSD as well. It chooses what to do from `RUBY_PLATFORM` (GSO and the PMTU discovery options are used on Linux alone) and from the `Socket` constants Ruby defines (the control messages), so on another system it takes whichever of these paths that system's constants allow; only Linux and OpenBSD have been tried.

The runtime needs a Fiber scheduler and blocks only the calling fiber ([fiber-scheduler.md](fiber-scheduler.md) uses the `async` gem, which is not a dependency of Raiha). `Raiha::Runtime::Threaded` runs on threads with no scheduler ([threads.md](threads.md)). `Raiha::Runtime::Workers` runs each worker in a Ractor of its own.

## How the runtime adapts

`Raiha::Runtime::Server`, `Raiha::Runtime::HTTP3::Server` and `Raiha::Runtime::Client` pass the `Raiha::QUIC::Config` you give them through three adjustments, so the same configuration works on every system:

- `UDP.batching`: a config without `max_transmit_size` gets `UDP::MAX_TRANSMIT` (65,507 bytes), so that one `Transmit` carries many datagrams at once.
- `UDP.pmtud`: `enable_pmtud` becomes false where a socket cannot keep IP from fragmenting (anywhere but Linux), so that no path MTU probe goes out in pieces.
- `UDP.ecn`: `:ipv4` is taken out of `ecn_address_families` where Ruby has no `IP_RECVTOS` (OpenBSD), so that IPv4 paths send Not-ECT. Such a system also drops an `IP_TOS` control message silently, and QUIC would otherwise count packets it never marked as ECT(0).

## Sending and receiving

| | Linux | OpenBSD |
| --- | --- | --- |
| Datagrams of one `Transmit` | One `sendmsg` with `UDP_SEGMENT` (GSO); the kernel cuts them | One `sendmsg` each |
| Fragmentation | Never; `IP_PMTUDISC_PROBE` / `IPV6_PMTUDISC_PROBE`, so a probe that is too large is lost or refused with `EMSGSIZE` | Left to the OS; the runtime sends no PMTU probe |
| ECN over IPv4 | Marked with `IP_TOS`, read with `IP_RECVTOS` | Not used |
| ECN over IPv6 | Marked with `IPV6_TCLASS`, read with `IPV6_RECVTCLASS` | Same as Linux |
| Address a datagram came to | `IP_PKTINFO`, `IPV6_RECVPKTINFO` | `IP_RECVDSTADDR`, `IPV6_RECVPKTINFO` |
| Address a datagram goes from | `IP_PKTINFO`, `IPV6_PKTINFO` | `IP_SENDSRCADDR`, `IPV6_PKTINFO` |

Datagrams are read with `recvmsg`, up to 64 at a time (`UDP::RECEIVE_BATCH`).

GSO falls back to one datagram per `sendmsg` when the kernel refuses it. `EIO` (a path without checksum offload, as in the ns-3 simulator) and `ENOPROTOOPT` (a kernel without `UDP_SEGMENT`) turn GSO off for the socket for good. `EINVAL` and `EMSGSIZE` turn it off only if the datagrams then go one by one, since otherwise the destination was at fault.

A control message that `sendmsg` refuses with `ENOPROTOOPT` or `EOPNOTSUPP` is left out from then on. The datagram goes again without the ECN mark, then without the source address, then without both. `EINVAL` may be the source address alone, as when Linux no longer has an IPv6 address, so the datagram goes again without the mark and nothing is left out for good.

Some errors drop one datagram and do not stop the socket:

- `ECONNREFUSED`, `EMSGSIZE`, `ENETUNREACH`, `EHOSTUNREACH` and `EADDRNOTAVAIL`
- `EINVAL` (such as port 0), `EACCES` (a broadcast address) and `EAFNOSUPPORT` (a family the socket does not send to)
- `EPERM` (a firewall) and `ENOBUFS`

A peer that spoofs its source chooses where responses go, so none of these is a reason to stop.

## Socket buffers

Each socket asks for 8 MiB of receive and send buffer (`UDP::BUFFER`), since the Linux default of about 212 KB drops a burst before it is read. Linux cuts the request to `net.core.rmem_max` / `net.core.wmem_max` and reports twice the size it keeps. Raise those limits for a busy server.

OpenBSD refuses a size over its limit (`SB_MAX`, 2 MiB) with `ENOBUFS`, so the socket asks for half as much, then half again, until the OS takes it. It never sets a buffer smaller than the one the socket already has.

## IPv4 and IPv6

A server binds `"::"` by default (`host: "::"`, `port: 443`).

On Linux, the socket clears `IPV6_V6ONLY` and takes IPv4 as well. Addresses of IPv4 peers are reported as IPv4 (`"192.0.2.1"`, not the IPv4-mapped `"::ffff:192.0.2.1"`), and are mapped back when sending.

OpenBSD's IPv6 sockets take IPv6 only, and clearing `IPV6_V6ONLY` fails. The runtime handles that as follows:

- `Server` and `HTTP3::Server` bound to `"::"` also bind `"0.0.0.0"` on the same port, so they take both families.
- `Workers` does the same for each worker. All the sockets are bound with `SO_REUSEPORT`.
- `Client.connect` binds `"::"` for an IPv6 server and `"0.0.0.0"` for an IPv4 one.
  - A connection on such a socket takes addresses of that family only (`Config#address_families`), so it moves to a preferred address of that family alone.
  - Where IPv6 is off and `"::"` cannot be bound, an IPv6 address fails at once and the next address of the host is tried.

A server bound to a specific address binds only that address. A server's preferred addresses (`Config#preferred_address`) each get a socket of their own unless a socket already bound takes them. A preferred address that cannot be bound makes `run` raise, so that no client is offered an address the server does not listen at.

## Workers and SO_REUSEPORT

`Raiha::Runtime::Workers` binds one socket per worker to the same address with `SO_REUSEPORT`. On Linux the kernel spreads datagrams over those sockets by 4-tuple. Elsewhere, as on OpenBSD, the kernel may give them all to one socket. The worker that has that socket then takes every new connection, and hands on what comes for the others' connections. More than one worker runs, but the load is not spread.

On OpenBSD with Ruby 4.0 (4.0.10 included), a worker can crash the whole process with `[BUG] Segmentation fault`, while it serves as well as when it stops. The bug is in Ruby, not in Raiha ([Bug #22453](https://bugs.ruby-lang.org/issues/22453)). Every Ractor but the main one runs its threads on Ruby's M:N scheduler. There, a thread that blocks may resume on another native thread, and on OpenBSD Ruby may then read the previous native thread's state after a fiber switch. Each worker has a Fiber scheduler and a thread of its own that waits on its ports, which is enough to hit it. Ruby's master branch has the fix. Until a Ruby 4.0 release has it, use `Raiha::Runtime::Server` rather than `Raiha::Runtime::Workers` on OpenBSD; with the load not spread there, one server loses little.

## Looking at a socket

`Raiha::Runtime::UDP#features` tells what a socket got on this system: its buffer sizes as the OS reports them, and whether it takes IPv4. It also tells which control messages it reads (`ecn_in`, `destination`) and sends (`source`, `ecn_out`), as they are now: a control message refused later turns its flag off. The runtime logs none of this.

```ruby
require "raiha"

["::", "0.0.0.0"].each do |host|
  udp = Raiha::Runtime::UDP.bind(host, 0)
  p [host, udp.features]
  udp.close
end
```

On Linux with `net.core.rmem_max` at 4 MiB, both sockets report:

```
#<data Raiha::Runtime::UDP::Features receive_buffer=8388608, send_buffer=8388608, ipv4=true, ecn_in=true, destination=true, source=true, ecn_out=true>
```

On OpenBSD 8.0 the following were seen:

- The buffers were 2097152.
- An IPv4 socket had `ecn_in=false` and `ecn_out=false`, with `destination` and `source` true.
- An IPv6 socket had everything true except `ipv4`.
- The servers' `Config#ecn_address_families` became `[:ipv6]`.
