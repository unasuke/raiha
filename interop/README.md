# raiha quic-interop-runner endpoint

Bundles raiha into the container shape that
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
expects: a Docker image with `run_endpoint.sh` at the root and a
small dispatcher (`interop/bin/raiha-interop`) that reads the
runner-provided environment variables and either binds a UDP server
on port 443 or runs the client's requests.

## Layout

```
interop/
├── Dockerfile            # multi-stage build on ruby:4.0-slim
├── run_endpoint.sh       # /app entrypoint exec'd by the runner
├── bin/
│   └── raiha-interop     # Ruby dispatcher, ROLE / TESTCASE_* aware
├── lib/raiha_interop/
│   ├── runner.rb         # reads the role and the testcase
│   ├── next_runner.rb    # the testcases taken in each role
│   ├── next_quic.rb
│   ├── next_server.rb / next_client.rb              # hq-interop
│   └── next_http3_server.rb / next_http3_client.rb  # http3
├── quic-interop-runner.no-sim.yml
├── run_interop_runner.sh
└── README.md
```

## Build

From the repo root:

```sh
docker build -t localhost/raiha-next-interop:latest -f interop/Dockerfile .
```

The build context must be the repo root because the Dockerfile copies
`Gemfile`, `lib/`, and `interop/`. The image entrypoint is
`run_endpoint.sh`, so any quic-interop-runner invocation works
out of the box.

## Local smoke test

Working files live under the repo's `tmp/` (gitignored). One-time
fixture setup:

```sh
mkdir -p tmp/raiha-{certs,www,downloads,qlog}
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout tmp/raiha-certs/priv.key \
  -out tmp/raiha-certs/cert.pem \
  -subj "/CN=raiha-server"
echo "interop test payload" > tmp/raiha-www/index.html
docker network create raiha-net
```

Run server (detached, `raiha-server` is reachable from the client
container by name on the bridge network):

```sh
docker run -d --name raiha-server --network raiha-net \
  -e ROLE=server -e TESTCASE_SERVER=handshake -e BIND_PORT=4433 \
  -e SSLKEYLOGFILE=/logs/keylog.txt -e QLOGDIR=/logs/qlog \
  -v $(pwd)/tmp/raiha-certs:/certs:ro \
  -v $(pwd)/tmp/raiha-www:/www:ro \
  -v $(pwd)/tmp/raiha-qlog:/logs \
  localhost/raiha-next-interop:latest
```

Client:

```sh
docker run --rm --network raiha-net \
  -e ROLE=client -e TESTCASE_CLIENT=handshake \
  -e REQUESTS=https://raiha-server:4433/index.html \
  -e DOWNLOADS=/downloads \
  -v $(pwd)/tmp/raiha-downloads:/downloads \
  localhost/raiha-next-interop:latest
```

## Running with quic-interop-runner

```sh
git clone --depth 1 https://github.com/quic-interop/quic-interop-runner tmp/quic-interop-runner
cd tmp/quic-interop-runner
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# Add raiha to implementations_quic.json as "raiha-next":
#   "raiha-next": {
#     "image": "localhost/raiha-next-interop:latest",
#     "url": "https://github.com/unasuke/raiha",
#     "role": "both"
#   }
```

`-c` selects the client implementation, `-s` the server. `-t`
restricts the testcases to run.

### The sim-less compose

The runner's own `docker-compose.yml` puts the ns-3 simulator between
the client and the server. Where that cannot run (see "With the ns-3
simulator" below), the repo ships a sim-less compose at
`interop/quic-interop-runner.no-sim.yml`, so client and server share a
plain bridge network. `interop/run_interop_runner.sh` copies it into
the runner's clone and runs `run.py` on it with the arguments given:

```sh
PYTHON=$PWD/tmp/quic-interop-runner/.venv/bin/python \
  interop/run_interop_runner.sh -c raiha-next -s raiha-next \
  -t handshake,transfer,multiplexing,retry,chacha20,keyupdate,http3,resumption,zerortt -d
```

The runner never takes the compose down, so a network it made
outlives it, and one on the same addresses (193.167.x.x, which
`trace.py` fixes) stops the next run from making its own, whichever
checkout or compose left it. The script makes the network afresh:
before the run it removes the networks on 193.167.x.x with the
stopped containers on them and those named `sim`, `client` and
`server`, and after the run it removes its own the same way. A
container still running is left alone, and the run does not start.
`RUNNER_DIR` points it at another clone of the runner.

The runner's testcase verification is pcap-driven via pyshark and
needs `tshark` / `editcap` to inspect QUIC packets, Wireshark 4.4 or
later. The sim-less compose pins the containers to
`193.167.{0,100}.100` (the IPs that `quic-interop-runner/trace.py`
hardcodes) and sets `NETWORK_SIMULATOR=none`, under which each
endpoint captures its own trace with tcpdump (`run_endpoint.sh`).

The CI job `next-interop-runner` runs the nine above. versionnegotiation
is implemented on both sides but left out, as the runner cannot run it
yet: `testcases_quic.py` defines `TestCaseVersionNegotiation` but
leaves it out of `TESTCASES_QUIC`, so `-t` does not take it, and its
check reads `p.scid` off each packet `get_vnp` gives, which is a whole
packet rather than its QUIC layer, so it raises `AttributeError` and
ends the run. Listed and read as `p.quic.scid`, it succeeds between
raiha-next and itself (checked 2026-10-22, runner at `1d6f655`). Before
adding it back to the job, check the runner upstream for a fix or an
issue on this.

## Supported testcases

The image runs the next release of raiha (`Raiha::QUIC`) with
hq-interop (HTTP/0.9 over QUIC), and HTTP/3 (`Raiha::HTTP3`) for
http3: `interop/lib/raiha_interop/next_runner.rb` hands the role to
`NextServer` or `NextClient`, or to `NextHTTP3Server` or
`NextHTTP3Client` for http3.

| testcase | client | server |
|----------|--------|--------|
| `handshake`, `transfer`, `multiplexing` | a stream for each request | the file of each path under `WWW` |
| `retry` | follows the Retry | sends a Retry to each client whose address is not validated |
| `chacha20` | offers `TLS_CHACHA20_POLY1305_SHA256` alone, without GREASE | as for `handshake` |
| `keyupdate` | updates keys after the first hundred packets, as it always does | as for `transfer` |
| `versionnegotiation` | elicits a Version Negotiation packet with an Initial of draft-29, which Wireshark reads the long header of, unlike a version reserved for negotiation | answers a version it does not take with a Version Negotiation packet |
| `http3` | a GET over HTTP/3 for each request, on a stream of its own | the file of each path under `WWW` with 200, over HTTP/3 |
| `resumption` | the first request on a connection that waits for a ticket, the rest on a second that resumes it | gives tickets sealed with a key made at random as it starts |
| `zerortt` | as for `resumption`, with the rest in 0-RTT, asked again in 1-RTT if the server rejects it | as for `resumption`, and takes 0-RTT, recorded with no time to warm up |
| `multiconnect` | each request on a connection of its own, one after another | as for `handshake` |
| `ecn` | as for `handshake`; its packets are marked ECT(0), as all are | as for `handshake` |
| `connectionmigration` | the runner gives it `transfer`: it moves to the server's preferred address, IPv6 first, once the handshake is confirmed and one of its connection IDs acknowledged | offers its own first IPv4 and IPv6 addresses on port 4434 as its preferred address, listens there too, and moves there once it has validated the client's path to it |

Everything else returns exit status 127, which the runner reports as
"not implemented". The runner gives several
testcases another's name: `blackhole`, `amplificationlimit`,
`transferloss`, `transfercorruption`, `rebind-port`, `rebind-addr`,
`ipv6` and the `goodput` and `crosstraffic` measurements are `transfer`
to both, `longrtt` is `handshake`, and `handshakeloss` and
`handshakecorruption` are `multiconnect`, and `connectionmigration` is
`transfer` to the client.

The server listens on `[::]:443`, which takes IPv4 as well, and the
client binds `::` and looks the server's name up for an address of
either family, so that it reaches `server6` for `ipv6`. A client the
NAT of `rebind-port` or `rebind-addr` moves is taken where it moves:
the server validates the new path, and the old one again, and goes on
sending there.

### With the ns-3 simulator

The testcases of loss, corruption, delay and bandwidth need the
runner's own `docker-compose.yml`, with the ns-3 simulator between the
client and the server. That takes Docker Engine 28.1 or later, for its
`interface_name:`, and Wireshark 4.4 or later for the runner's `tshark`.
Under the docker shim of podman 5.x, the compose errors out at
`interface_name:`, and with those lines stripped the simulator's
container starts but passes no packets on, so CI stays on the sim-less
compose.

`run_endpoint.sh` does what the simulator's endpoint image does in its
`setup.sh`: the routes to `193.167.0.0/16` and `fd00:cafe:cafe::/48` go
through the simulator, `.2` of the endpoint's network, the direct ones
go, and the checksum offload is turned off, as the simulator passes on
only datagrams whose checksums are valid; the client waits for the
simulator to listen on port 57832. The sim-less compose sets
`NETWORK_SIMULATOR=none`, which leaves all of that out. With the
offload off the kernel refuses GSO (EIO), and the runtime's socket sends
the datagrams of a Transmit one by one.

The upstream compose raises the endpoints' locked memory to 64 MiB. Where
the hard limit is lower, as in an LXD container (8 MiB), the containers
do not start; raiha locks no memory, so an override that lowers it is
enough:

```yaml
# memlock.yml, next to the runner's docker-compose.yml
services:
  server:
    ulimits:
      memlock: 8388608
  client:
    ulimits:
      memlock: 8388608
```

```sh
docker build -t localhost/raiha-next-interop:latest -f interop/Dockerfile .
cd tmp/quic-interop-runner
COMPOSE_FILE=docker-compose.yml:memlock.yml python run.py -c raiha-next -s raiha-next \
  -t handshakeloss,transferloss,handshakecorruption,transfercorruption,longrtt,blackhole,amplificationlimit,ecn,goodput,crosstraffic
COMPOSE_FILE=docker-compose.yml:memlock.yml python run.py -c raiha-next -s raiha-next \
  -t rebind-port,rebind-addr,connectionmigration,ipv6
```

`rebind-port`, `rebind-addr`, `connectionmigration` and `ipv6` need the
simulator too: the sim-less compose neither rebinds the client nor
carries IPv6.

The runner leaves the log directory and the networks of a run behind;
give each run a `--log-dir` of its own, and take the networks on
`193.167.x.x` down before the next.

Built with `--build-arg RAIHA_STARTUP=rapid_start`, the image
starts its paths with Rapid Start (`Congestion::Startup::RapidStart`);
under a tag and a name of its own in `implementations_quic.json`, the
goodput of the two can be set side by side.

## Environment variables

| variable | purpose |
|----------|---------|
| `ROLE` | `server` or `client` |
| `TESTCASE_SERVER` / `TESTCASE_CLIENT` | per-role testcase selector (`TESTCASE` inside the runner's containers) |
| `REQUESTS` | client only — the URLs to fetch, separated by spaces |
| `WWW` | server only — document root for static responses |
| `DOWNLOADS` | client only — directory to write fetched files into |
| `CERTS` | server only — directory containing `cert.pem` / `priv.key` |
| `QLOGDIR` | optional — emit qlog files to this directory |
| `SSLKEYLOGFILE` | optional — path for the standard TLS key log |
| `BIND_PORT` | server only — override the default port 443 |
| `RAIHA_STARTUP` | optional — `rapid_start` to start paths with Rapid Start |
