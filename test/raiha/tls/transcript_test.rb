require "test_helper"
require "raiha/tls/test"

class RaihaNextTLSTranscriptTest < Minitest::Test
  TLS = Raiha::TLS
  Transcript = TLS::Transcript
  RFC8448 = TLS::Test::RFC8448

  def test_rfc8448_simple_1rtt
    s = RFC8448::Simple1RTT
    transcript = Transcript.new(hashes: [:sha256, :sha384])
    transcript << s::CLIENT_HELLO << s::SERVER_HELLO
    transcript.select!(:sha256)
    assert_equal :sha256, transcript.selected
    assert_equal_bin s::HELLO_TRANSCRIPT_HASH, transcript.digest
    transcript << s::ENCRYPTED_EXTENSIONS << s::CERTIFICATE << s::CERTIFICATE_VERIFY << s::SERVER_FINISHED
    assert_equal_bin s::SERVER_FINISHED_TRANSCRIPT_HASH, transcript.digest
    transcript << s::CLIENT_FINISHED
    assert_equal_bin s::CLIENT_FINISHED_TRANSCRIPT_HASH, transcript.digest
  end

  # A client runs both hashes until the ServerHello names the suite.
  def test_both_hashes_run_until_selection
    s = RFC8448::Simple1RTT
    transcript = Transcript.new(hashes: [:sha256, :sha384])
    transcript << s::CLIENT_HELLO
    assert_nil transcript.selected
    assert_equal_bin TLS::Crypto.hash(:sha384, s::CLIENT_HELLO), transcript.digest(:sha384)
    assert_equal_bin TLS::Crypto.hash(:sha256, s::CLIENT_HELLO), transcript.digest(:sha256)
    transcript.select!(:sha256)
    assert_raises(TLS::UsageError) { transcript.digest(:sha384) }
  end

  # RFC 8448 section 5: ClientHello1 becomes message_hash once the
  # HelloRetryRequest has fixed the hash.
  def test_rfc8448_hello_retry_request
    h = RFC8448::HelloRetryRequest
    transcript = Transcript.new(hashes: [:sha256, :sha384])
    transcript << h::CLIENT_HELLO_1
    transcript.select!(:sha256)
    transcript.restart_with_message_hash!
    transcript << h::HELLO_RETRY_REQUEST << h::CLIENT_HELLO_2 << h::SERVER_HELLO
    assert_equal_bin h::HELLO_TRANSCRIPT_HASH, transcript.digest
    transcript << h::ENCRYPTED_EXTENSIONS << h::CERTIFICATE << h::CERTIFICATE_VERIFY << h::SERVER_FINISHED
    assert_equal_bin h::SERVER_FINISHED_TRANSCRIPT_HASH, transcript.digest
  end

  # A stateless server keeps only Hash(ClientHello1), in the cookie.
  def test_restart_from_a_kept_client_hello_hash
    h = RFC8448::HelloRetryRequest
    transcript = Transcript.new(hashes: [:sha256])
    transcript << h::CLIENT_HELLO_1
    transcript.select!(:sha256)
    transcript.restart_with_message_hash!(digest: TLS::Crypto.hash(:sha256, h::CLIENT_HELLO_1))
    transcript << h::HELLO_RETRY_REQUEST << h::CLIENT_HELLO_2 << h::SERVER_HELLO
    assert_equal_bin h::HELLO_TRANSCRIPT_HASH, transcript.digest
  end

  # The PSK binder covers the ClientHello up to the binders: add it in two
  # parts and take the digest in between.
  def test_client_hello_added_in_two_parts
    r = RFC8448::Resumed0RTT
    transcript = Transcript.new(hashes: [:sha256])
    transcript << r::CLIENT_HELLO_PREFIX
    assert_equal_bin TLS::Crypto.hash(:sha256, r::CLIENT_HELLO_PREFIX), transcript.digest(:sha256)
    transcript << r::CLIENT_HELLO.byteslice(r::CLIENT_HELLO_PREFIX.bytesize..)
    assert_equal_bin TLS::Crypto.hash(:sha256, r::CLIENT_HELLO), transcript.digest(:sha256)
  end

  def test_restart_accepts_client_hello_added_in_two_parts
    h = RFC8448::HelloRetryRequest
    transcript = Transcript.new(hashes: [:sha256])
    transcript << h::CLIENT_HELLO_1.byteslice(0, 2) << h::CLIENT_HELLO_1.byteslice(2..)
    transcript.select!(:sha256)
    transcript.restart_with_message_hash!
    transcript << h::HELLO_RETRY_REQUEST << h::CLIENT_HELLO_2 << h::SERVER_HELLO
    assert_equal_bin h::HELLO_TRANSCRIPT_HASH, transcript.digest
  end

  def test_restart_preconditions
    h = RFC8448::HelloRetryRequest
    unselected = Transcript.new(hashes: [:sha256]) << h::CLIENT_HELLO_1
    assert_raises(TLS::UsageError) { unselected.restart_with_message_hash! }

    partial = Transcript.new(hashes: [:sha256]) << h::CLIENT_HELLO_1.byteslice(0, 10)
    partial.select!(:sha256)
    assert_raises(TLS::UsageError) { partial.restart_with_message_hash! }

    two = Transcript.new(hashes: [:sha256]) << h::CLIENT_HELLO_1 << h::HELLO_RETRY_REQUEST
    two.select!(:sha256)
    assert_raises(TLS::UsageError) { two.restart_with_message_hash! }

    not_client_hello = Transcript.new(hashes: [:sha256]) << h::SERVER_HELLO
    not_client_hello.select!(:sha256)
    assert_raises(TLS::UsageError) { not_client_hello.restart_with_message_hash! }

    once = Transcript.new(hashes: [:sha256]) << h::CLIENT_HELLO_1
    once.select!(:sha256)
    once.restart_with_message_hash!
    assert_raises(TLS::UsageError) { once.restart_with_message_hash! }
  end

  def test_selection_rules
    transcript = Transcript.new(hashes: [:sha256, :sha384])
    assert_raises(TLS::UsageError) { transcript.digest }
    assert_raises(TLS::UsageError) { transcript.select!(:sha512) }
    transcript.select!(:sha384)
    transcript.select!(:sha384)
    assert_raises(TLS::UsageError) { transcript.select!(:sha256) }
  end

  def test_constructor_takes_one_or_two_distinct_hashes
    assert_raises(ArgumentError) { Transcript.new(hashes: []) }
    assert_raises(ArgumentError) { Transcript.new(hashes: [:sha256, :sha256]) }
    assert_raises(ArgumentError) { Transcript.new(hashes: [:sha256, :sha384, :sha256]) }
    assert_raises(ArgumentError) { Transcript.new(hashes: [:md5]) }
  end

  # NewSessionTicket and KeyUpdate never enter the transcript.
  def test_transcript_messages
    assert_equal Set[1, 2, 5, 8, 11, 13, 15, 20, 25, 254], Transcript::TRANSCRIPT_MESSAGES
    refute_includes Transcript::TRANSCRIPT_MESSAGES, TLS::Handshake::NewSessionTicket::MSG_TYPE
    refute_includes Transcript::TRANSCRIPT_MESSAGES, TLS::Handshake::KeyUpdate::MSG_TYPE
    assert Ractor.shareable?(Transcript::TRANSCRIPT_MESSAGES)
  end
end
