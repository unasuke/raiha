require "test_helper"
require "support/rfc8448_test_vector"
require "raiha/tls/peer"
require "raiha/tls/config"
require "raiha/tls/handshake"
require "raiha/tls/error"

class RaihaTLSPeerTest < Minitest::Test
  class Subject < Raiha::TLS::Peer
    def initialize(config)
      @config = config
    end

    def call_verify(handshake, raw_bytes)
      verify_transcript_roundtrip!(handshake, raw_bytes)
    end
  end

  def test_verify_is_noop_when_config_disables_it
    config = Raiha::TLS::Config.new(
      cipher_suites: Raiha::TLS::Config::DEFAULT_CIPHER_SUITES,
      supported_groups: Raiha::TLS::Config::DEFAULT_SUPPORTED_GROUPS,
      transcript_hash_verify: false,
    )
    subject = Subject.new(config)
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO)
    refute_nil handshake
    # bytes intentionally differ; should still not raise because flag is off
    assert_nil subject.call_verify(handshake, "\x00\x00\x00\x00")
  end

  def test_verify_passes_when_serialize_matches_raw_bytes
    config = Raiha::TLS::Config.new(
      cipher_suites: Raiha::TLS::Config::DEFAULT_CIPHER_SUITES,
      supported_groups: Raiha::TLS::Config::DEFAULT_SUPPORTED_GROUPS,
      transcript_hash_verify: true,
    )
    subject = Subject.new(config)
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO)
    refute_nil handshake
    assert_nil subject.call_verify(handshake, RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO)
  end

  def test_verify_raises_on_mismatch_with_handshake_type_symbol_and_byte_info
    config = Raiha::TLS::Config.new(
      cipher_suites: Raiha::TLS::Config::DEFAULT_CIPHER_SUITES,
      supported_groups: Raiha::TLS::Config::DEFAULT_SUPPORTED_GROUPS,
      transcript_hash_verify: true,
    )
    subject = Subject.new(config)
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO)
    refute_nil handshake
    # Flip a byte deep inside the message so prefix_match > 0 and
    # sizes still match.
    tampered = RFC8448_SIMPLE_1RTT_HANDSHAKE_CLIENT_HELLO.dup
    tampered.setbyte(10, tampered.getbyte(10) ^ 0xff)

    error = assert_raises(Raiha::TLS::TranscriptRoundtripError) do
      subject.call_verify(handshake, tampered)
    end
    assert_match(/client_hello/, error.message)
    assert_match(/raw_bytes=\d+B/, error.message)
    assert_match(/serialize=\d+B/, error.message)
    assert_match(/first diff at byte 10/, error.message)
  end
end
