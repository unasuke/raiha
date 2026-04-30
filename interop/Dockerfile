# quic-interop-runner endpoint image for raiha.
#
# The image provides a small Ruby script (raiha-interop) that the
# runner invokes via run_endpoint.sh. ROLE / TESTCASE_* / CERTS /
# WAITFORSERVER / WWW / DOWNLOADS / QLOGDIR / SSLKEYLOGFILE come in
# as environment variables; raiha-interop reads them and either
# binds a UDP server or runs a one-shot client.

FROM ruby:4.0-slim AS builder
ENV LANG=C.UTF-8 BUNDLE_PATH=/usr/local/bundle
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential libssl-dev pkg-config git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Gemfile Gemfile.lock raiha.gemspec ./
COPY lib ./lib
RUN bundle config set --local without 'development test' \
 && bundle install

FROM ruby:4.0-slim
ENV LANG=C.UTF-8 BUNDLE_PATH=/usr/local/bundle
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libssl3 ca-certificates iproute2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/local/bundle /usr/local/bundle
COPY lib ./lib
COPY interop ./interop
RUN chmod +x /app/interop/run_endpoint.sh /app/interop/bin/raiha-interop

ENV PATH=/app/interop/bin:$PATH \
    RUBYOPT="-W0"

ENTRYPOINT ["/app/interop/run_endpoint.sh"]
