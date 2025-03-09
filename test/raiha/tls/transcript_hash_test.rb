require "test_helper"
require "openssl"
require "raiha/tls/transcript_hash"
require "support/rfc8448_test_vector"

class RaihaTLSTranscriptHashTest < Minitest::Test
  def test_hash
    transcript_hash = Raiha::TLS::TranscriptHash.new
    transcript_hash.digest_algorithm = "sha256"
    transcript_hash[:client_hello] = RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO

    digest = OpenSSL::Digest.new("sha256")
    digest.reset
    digest.update(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO)
    digest_expected = digest.digest
    assert_equal_bin digest_expected, transcript_hash.hash

    transcript_hash[:server_hello] = RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO
    digest.reset
    digest.update(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO)
    digest.update(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_HELLO)
    digest_expected = digest.digest
    assert_equal_bin digest_expected, transcript_hash.hash
  end

  def test_hash_with_hello_retry_request
    skip
  end
end
