require "test_helper"
require "raiha/quic/retry_token"
require "raiha/quic/protocol/connection_id"

class RaihaQuicRetryTokenTest < Minitest::Test
  KEY = "retry-cookie-key".b * 2

  def test_mint_and_verify_round_trip
    odcid = "ABCDEFGH".b
    peer = "192.0.2.1:1234".b

    token = Raiha::Quic::RetryToken.mint(
      retry_key: KEY,
      peer_address_bytes: peer,
      original_destination_connection_id: odcid
    )

    assert_equal odcid, Raiha::Quic::RetryToken.verify(
      retry_key: KEY,
      token: token,
      peer_address_bytes: peer
    )
  end

  def test_verify_rejects_modified_token
    token = Raiha::Quic::RetryToken.mint(
      retry_key: KEY,
      peer_address_bytes: "peer1".b,
      original_destination_connection_id: "ABCDEFGH".b
    )
    tampered = token.dup
    tampered.setbyte(0, tampered.getbyte(0) ^ 0x01)

    assert_nil Raiha::Quic::RetryToken.verify(
      retry_key: KEY,
      token: tampered,
      peer_address_bytes: "peer1".b
    )
  end

  def test_verify_rejects_wrong_peer
    token = Raiha::Quic::RetryToken.mint(
      retry_key: KEY,
      peer_address_bytes: "peer1".b,
      original_destination_connection_id: "ABCDEFGH".b
    )

    assert_nil Raiha::Quic::RetryToken.verify(
      retry_key: KEY,
      token: token,
      peer_address_bytes: "peer2".b
    )
  end

  def test_verify_rejects_expired_token
    minted_at = Time.at(1_700_000_000)
    token = Raiha::Quic::RetryToken.mint(
      retry_key: KEY,
      peer_address_bytes: "peer1".b,
      original_destination_connection_id: "ABCDEFGH".b,
      lifetime: 30,
      now: minted_at
    )

    assert_nil Raiha::Quic::RetryToken.verify(
      retry_key: KEY,
      token: token,
      peer_address_bytes: "peer1".b,
      now: minted_at + 60
    )
  end

  def test_verify_accepts_token_within_lifetime
    minted_at = Time.at(1_700_000_000)
    token = Raiha::Quic::RetryToken.mint(
      retry_key: KEY,
      peer_address_bytes: "peer1".b,
      original_destination_connection_id: "ABCDEFGH".b,
      lifetime: 30,
      now: minted_at
    )

    assert_equal "ABCDEFGH".b, Raiha::Quic::RetryToken.verify(
      retry_key: KEY,
      token: token,
      peer_address_bytes: "peer1".b,
      now: minted_at + 10
    )
  end

  def test_mint_accepts_connection_id_object
    cid = Raiha::Quic::Protocol::ConnectionID.from_bytes("ABCDEFGH".b)
    token = Raiha::Quic::RetryToken.mint(
      retry_key: KEY,
      peer_address_bytes: "peer".b,
      original_destination_connection_id: cid
    )
    assert_equal "ABCDEFGH".b, Raiha::Quic::RetryToken.verify(
      retry_key: KEY,
      token: token,
      peer_address_bytes: "peer".b
    )
  end

  def test_verify_returns_nil_for_short_token
    assert_nil Raiha::Quic::RetryToken.verify(
      retry_key: KEY,
      token: "short".b,
      peer_address_bytes: "peer".b
    )
  end

  def test_mint_rejects_empty_key
    assert_raises(ArgumentError) do
      Raiha::Quic::RetryToken.mint(
        retry_key: "",
        peer_address_bytes: "peer".b,
        original_destination_connection_id: "ABCDEFGH".b
      )
    end
  end
end
