require "raiha/next/quic"
require "raiha/next/support/tls_pair"

# TLS settings for QUIC connections in tests: the QUIC profile, an ALPN
# both ends share, and a registry that keeps the transport parameters.
module NextQUICTLS
  TLS = Raiha::Next::TLS
  QUIC = Raiha::Next::QUIC
  REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)
  ALPN = ["hq-interop"].freeze
  # The wall clock the test certificates are valid at.
  NOW = NextTLSPair::NOW

  module_function

  def client_config(**options) = NextTLSPair.client_config(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY, **options)

  def server_config(**options) = NextTLSPair.server_config(profile: TLS::Profile::QUIC, alpn: ALPN, registry: REGISTRY, **options)

  def client_keyring(config: client_config) = TLS::Keyring.client(config:)

  def server_keyring(config: server_config) = NextTLSPair.server_keyring(config:)
end
