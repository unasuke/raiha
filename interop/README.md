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
git clone https://github.com/quic-interop/quic-interop-runner /tmp/qir
cd /tmp/qir
# Add raiha to the local implementations.json:
#   "raiha": {
#     "image": "raiha-interop",
#     "url": "...",
#     "role": "both"
#   }
python run.py -c raiha -s raiha -t handshake
python run.py -c raiha -s quic-go -t handshake
```

`-c` selects the client implementation, `-s` the server. `-t`
restricts the testcases to run.

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
