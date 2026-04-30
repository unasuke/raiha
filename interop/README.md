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

The runner expects a server cert at `/certs/cert.pem` and a private
key at `/certs/priv.key`. To exercise the image without the runner:

```sh
mkdir -p /tmp/raiha-certs /tmp/raiha-www /tmp/raiha-downloads
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /tmp/raiha-certs/priv.key \
  -out /tmp/raiha-certs/cert.pem \
  -days 1 -nodes -subj "/CN=raiha.test"
echo hello > /tmp/raiha-www/hello.txt

docker run --rm -p 4433:443/udp \
  -e ROLE=server \
  -e TESTCASE_SERVER=handshake \
  -v /tmp/raiha-certs:/certs:ro \
  -v /tmp/raiha-www:/www:ro \
  raiha-interop
```

In another terminal:

```sh
docker run --rm \
  -e ROLE=client \
  -e TESTCASE_CLIENT=handshake \
  -e WAITFORSERVER=host.docker.internal:4433 \
  -v /tmp/raiha-downloads:/downloads \
  raiha-interop
```

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
| `handshake` | claimed |

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
