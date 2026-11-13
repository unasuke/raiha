require "test_helper"
require "prism"

# Only the TLS layer's Crypto and Verifier and the QUIC layer's Crypto may
# call OpenSSL; everything else goes through them. Comments are ignored, and
# a constant of our own named OpenSSL (KeyExchange::OpenSSL) is not a call
# into the library.
class RaihaOpenSSLHygieneTest < Minitest::Test
  LIB_DIR = File.expand_path("../../lib/raiha", __dir__)
  ALLOWED = { tls: %r{\Atls/(?:crypto|verifier)(?:\.rb\z|/)}, quic: %r{\Aquic/crypto(?:\.rb\z|/)} }
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
    Dir.glob("**/*.rb", base: LIB_DIR).sort
  end

  def allowed?(file) = ALLOWED.each_value.any? { |pattern| file.match?(pattern) }

  def test_openssl_is_called_only_from_crypto_and_verifier
    offenders = files.reject { |file| allowed?(file) }.to_h { |file| [file, openssl_lines(File.join(LIB_DIR, file))] }
    assert_empty offenders.reject { |_, lines| lines.empty? }
  end

  # Guards against a pattern silently matching nothing.
  def test_each_layer_does_call_openssl
    ALLOWED.each do |layer, pattern|
      refute_empty files.grep(pattern).flat_map { |file| openssl_lines(File.join(LIB_DIR, file)) }, layer
    end
  end
end
