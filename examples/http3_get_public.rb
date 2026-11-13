# An HTTP/3 GET to a few public HTTP/3 servers with the runtime's client,
# printing each response's status, headers and the start of its body.
# With no arguments it asks a built-in list; URLs given as arguments take
# its place. The servers' certificates are verified against the system's
# trust store (OpenSSL::X509::DEFAULT_CERT_FILE). It needs the network, so
# no test runs it; a target that fails prints its error, and the next goes
# on.
#
# Usage:
#   bundle exec ruby -Ilib examples/http3_get_public.rb
#   bundle exec ruby -Ilib examples/http3_get_public.rb https://cloudflare-quic.com/
#
# Expected output (one block for each target):
#   https://cloudflare-quic.com/
#     status: 200
#     headers:
#       content-type: text/html
#       ...
#     body (... bytes, first 80): "..."

require "raiha/runtime"
# The scheduler of async reads with IO::Buffer, which Ruby 4.0 warns is
# experimental.
Warning[:experimental] = false
require "async"
require "openssl"
require "uri"

Runtime = Raiha::Next::Runtime
QUIC = Raiha::Next::QUIC
TLS = Raiha::Next::TLS
REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)

DEFAULT_TARGETS = [
  "https://cloudflare-quic.com/",
  "https://quic.nginx.org/",
  "https://nghttp2.org/"
].freeze

# The certificates of the system's trust store, DER-encoded.
def trust_anchors
  pem = File.read(OpenSSL::X509::DEFAULT_CERT_FILE)
  pem.scan(/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/m).map { |cert| OpenSSL::X509::Certificate.new(cert).to_der }
end

def print_response(url, response)
  puts url
  puts "  status: #{response.status}"
  puts "  headers:"
  response.headers.each { |name, value| puts "    #{name}: #{value}" }
  puts "  body (#{response.body.bytesize} bytes, first 80): #{response.body.byteslice(0, 80).inspect}"
end

tls = TLS::Config.client(trust_anchors:, profile: TLS::Profile::QUIC, alpn: [Runtime::HTTP3::Client::ALPN], registry: REGISTRY)
targets = ARGV.empty? ? DEFAULT_TARGETS : ARGV

Async do
  targets.each do |url|
    uri = URI(url)
    response = Runtime::Client.connect(uri.host, uri.port, config: QUIC::Config.new, tls_config: tls, keyring: TLS::Keyring.client(config: tls)) do |session|
      Runtime::HTTP3::Client.new(session).get(uri.request_uri)
    end
    print_response(url, response)
  rescue StandardError => error
    puts url
    puts "  error: #{error.class}: #{error.message}"
  end
end
