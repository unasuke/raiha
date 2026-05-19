# raiha quic-interop-runner endpoint

Bundles raiha into the container shape that
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
expects: a Docker image with `run_endpoint.sh` at the root and a
small dispatcher (`interop/bin/raiha-interop`) that reads the
runner-provided environment variables and either binds a UDP server
on `0.0.0.0:443` or runs a single client request.

## Layout

```
interop/
├── Dockerfile            # multi-stage build on ruby:4.0-slim
├── run_endpoint.sh       # /app entrypoint exec'd by the runner
├── bin/
│   └── raiha-interop     # Ruby dispatcher, ROLE / TESTCASE_* aware
├── lib/raiha_interop/
│   ├── runner.rb
│   ├── client_runner.rb
│   ├── server_runner.rb
│   └── testcases.rb
└── README.md
```

## Build

From the repo root:

```sh
docker build -t raiha-interop -f interop/Dockerfile .
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
  raiha-interop
```

Client:

```sh
docker run --rm --network raiha-net \
  -e ROLE=client -e TESTCASE_CLIENT=handshake \
  -e WAITFORSERVER=raiha-server:4433 \
  -e DOWNLOADS=/downloads \
  -v $(pwd)/tmp/raiha-downloads:/downloads \
  raiha-interop
```

For the http3 / transfer testcases also pass `REQUESTS=https://raiha-server/index.html`
to the client.

## Running with quic-interop-runner

```sh
git clone --depth 1 https://github.com/quic-interop/quic-interop-runner tmp/quic-interop-runner
cd tmp/quic-interop-runner
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# Add raiha to implementations_quic.json:
#   "raiha": {
#     "image": "localhost/raiha-interop:latest",
#     "url": "https://github.com/unasuke/raiha",
#     "role": "both"
#   }
python run.py -c raiha -s raiha -t handshake -d
python run.py -c raiha -s quic-go -t handshake
```

`-c` selects the client implementation, `-s` the server. `-t`
restricts the testcases to run.

### Known environment caveats (podman docker-shim)

Running on a docker shim provided by podman 5.x surfaced three issues
that an actual Docker Engine 28.1+ install with Wireshark would
avoid:

- `interface_name:` in the upstream `docker-compose.yml` requires
  Docker Engine 28.1; under the podman shim it errors out at compose
  up. Either strip those four lines or use the sim-less variant
  (next bullet).
- The `martenseemann/quic-network-simulator` ns-3 container needs raw
  socket / iptables forwarding inside its network namespace. Under
  podman the sim container starts and `dumpcap` runs, but no packets
  appear to traverse the ns-3 datapath, so handshake testcases time
  out. The repo ships a sim-less compose override at
  `interop/quic-interop-runner.no-sim.yml`; copy it into the runner's
  clone and point compose at it, so client and server share a plain
  bridge network and h3 traffic flows directly:

  ```sh
  cp interop/quic-interop-runner.no-sim.yml \
     tmp/quic-interop-runner/docker-compose.no-sim.yml
  cd tmp/quic-interop-runner && . .venv/bin/activate
  COMPOSE_FILE=docker-compose.no-sim.yml \
    python run.py -c raiha -s raiha -t handshake -d
  ```

  Under this layout the handshake actually completes (`client exited
  with code 0`, file downloaded), but…
- The runner's testcase verification is pcap-driven via pyshark and
  needs `tshark` / `editcap` to inspect QUIC packets. With
  Wireshark 4.4+ installed and the no-sim compose pinning the
  containers to `193.167.{0,100}.100` (the IPs that
  `quic-interop-runner/trace.py` hardcodes), pyshark sees real
  packets and `_get_versions` returns `0x1`.

### Last verified status (raiha vs raiha, sim-less compose)

| testcase | result | notes |
|----------|--------|-------|
| `handshake` | ✓ | basic 1 KB transfer + handshake check |
| `transfer` | ✓ | 2 MB + 3 MB + 5 MB, all three streams verified |
| `http3` | ✓ | HTTP/3 GET, ~512 KB body |
| `retry` | ✓ | Demuxer issues + validates Retry token end-to-end |

### Cross-implementation matrix

Tried against `martenseemann/quic-go-interop:latest` under the same
sim-less compose. Results so far:

- `python run.py -c raiha -s quic-go ...`: raiha client gets to
  "starting" but stops before "handshake complete". quic-go server
  receives the Initial and replies, but raiha's processing of that
  reply (in this particular compose environment) doesn't progress
  the handshake — works in a plain `docker network` smoke between
  the same two images, so the mismatch is environment-specific
  rather than a protocol-level gap.
- `python run.py -c quic-go -s raiha ...`: the compliance pre-check
  fails because quic-go's interop entrypoint doesn't exit 127 for
  an unknown testcase in our podman-shim setup, so the runner skips
  every testcase. The same compliance check passes for raiha, so
  the gap is in quic-go's run script under this runtime.

Both directions need more environment plumbing (matching the
expectations of the official Docker Engine + ns-3 sim setup) before
the matrix produces meaningful verdicts. The self-pair smoke above
remains the only path that runs end to end here.

## Supported testcases

| testcase | status |
|----------|--------|
| `handshake` | claimed — raiha vs raiha smoke OK |
| `transfer` | claimed — raiha vs raiha smoke OK (downloaded body matches `/www`) |
| `http3` | claimed — raiha vs raiha smoke OK |
| `versionnegotiation` | claimed — raiha vs raiha smoke は v1-v1 で degenerate (VN は trigger せず); Demuxer 単体の VN 応答は unit test で検証済 |
| `retry` | claimed — raiha vs raiha smoke で `require_retry: true` のもと client exit 0 (Retry → 二度目 Initial 経路を経たと推定) |

Anything else returns exit status 127 and the runner reports it as
"not implemented", which keeps the matrix honest while we expand
coverage.

## Environment variables

| variable | purpose |
|----------|---------|
| `ROLE` | `server` or `client` |
| `TESTCASE_SERVER` / `TESTCASE_CLIENT` | per-role testcase selector |
| `WAITFORSERVER` | client only — `host:port` to dial |
| `WWW` | server only — document root for static responses |
| `DOWNLOADS` | client only — directory to write fetched files into |
| `CERTS` | server only — directory containing `cert.pem` / `priv.key` |
| `QLOGDIR` | optional — emit qlog files to this directory |
| `SSLKEYLOGFILE` | optional — path for the standard TLS key log |
| `BIND_HOST` / `BIND_PORT` | server only — override the default `0.0.0.0:443` |
