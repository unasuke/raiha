require "test_helper"
require "raiha/tls/config"

class RaihaTLSConfigTest < Minitest::Test
  def test_default_transcript_hash_verify_is_false
    config = Raiha::TLS::Config.new(
      cipher_suites: Raiha::TLS::Config::DEFAULT_CIPHER_SUITES,
      supported_groups: Raiha::TLS::Config::DEFAULT_SUPPORTED_GROUPS,
    )
    refute config.transcript_hash_verify
  end

  def test_transcript_hash_verify_can_be_enabled_via_keyword
    config = Raiha::TLS::Config.new(
      cipher_suites: Raiha::TLS::Config::DEFAULT_CIPHER_SUITES,
      supported_groups: Raiha::TLS::Config::DEFAULT_SUPPORTED_GROUPS,
      transcript_hash_verify: true,
    )
    assert config.transcript_hash_verify
  end

  def test_client_default_reads_env
    with_env("RAIHA_TRANSCRIPT_VERIFY", "1") do
      assert Raiha::TLS::Config.client_default.transcript_hash_verify
    end
    with_env("RAIHA_TRANSCRIPT_VERIFY", nil) do
      refute Raiha::TLS::Config.client_default.transcript_hash_verify
    end
  end

  def test_server_default_reads_env
    with_env("RAIHA_TRANSCRIPT_VERIFY", "1") do
      assert Raiha::TLS::Config.server_default.transcript_hash_verify
    end
    with_env("RAIHA_TRANSCRIPT_VERIFY", nil) do
      refute Raiha::TLS::Config.server_default.transcript_hash_verify
    end
  end

  private def with_env(name, value)
    previous = ENV[name]
    ENV[name] = value
    yield
  ensure
    ENV[name] = previous
  end
end
