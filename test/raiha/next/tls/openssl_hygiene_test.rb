require "raiha/next/test_helper"
require "prism"

# Only Crypto and Verifier may call OpenSSL; everything else in the TLS
# layer goes through them. Comments are ignored, and a constant of our own
# named OpenSSL (KeyExchange::OpenSSL) is not a call into the library.
class RaihaNextTLSOpenSSLHygieneTest < Minitest::Test
  TLS_DIR = File.expand_path("../../../../lib/raiha/next/tls", __dir__)
  ALLOWED = %r{\A(?:crypto|verifier)(?:\.rb\z|/)}
  # `OpenSSL::` or `OpenSSL.` that is not the tail of a longer constant path.
  OPENSSL = /(?<![\w:])(?:::)?OpenSSL(?:::|\.)/

  def openssl_lines(path)
    source = File.read(path)
    Prism.parse(source).comments.each do |comment|
      location = comment.location
      source[location.start_offset, location.length] = " " * location.length
    end
    source.each_line.with_index(1).select { |line, _| line.match?(OPENSSL) }.map { |line, number| "#{number}: #{line.strip}" }
  end

  def files
    Dir.glob("**/*.rb", base: TLS_DIR).sort
  end

  def test_openssl_is_called_only_from_crypto_and_verifier
    offenders = files.reject { |file| file.match?(ALLOWED) }.to_h { |file| [file, openssl_lines(File.join(TLS_DIR, file))] }
    assert_empty offenders.reject { |_, lines| lines.empty? }
  end

  # Guards against the pattern silently matching nothing.
  def test_crypto_does_call_openssl
    refute_empty files.grep(ALLOWED).flat_map { |file| openssl_lines(File.join(TLS_DIR, file)) }
  end
end
