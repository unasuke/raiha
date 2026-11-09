require "raiha/next/test_helper"
require "raiha/next/quic"

# The connection IDs the peer issues: how many are kept, which are retired
# and sent back, and what breaks the rules.
class RaihaNextQUICPeerConnectionIDsTest < Minitest::Test
  QUIC = Raiha::Next::QUIC

  def ids(limit: 4, first: "\x00".b * 8) = QUIC::PeerConnectionIDs.new(first, stateless_reset_token: "t".b * 16, limit:)

  def new_id(sequence_number, retire_prior_to: 0, connection_id: [sequence_number].pack("C") * 8, token: [sequence_number].pack("C") * 16)
    QUIC::Wire::Frame::NewConnectionID.new(sequence_number:, retire_prior_to:, connection_id:, stateless_reset_token: token)
  end

  def retirements(ids)
    out = []
    while (frame, = ids.next_frame(100))
      out << frame.sequence_number
    end
    out
  end

  def assert_violation(code, &)
    error = assert_raises(QUIC::Violation, &)
    assert_equal code, error.code, error.message
  end

  def test_up_to_the_limit
    peer = ids
    (1..3).each { peer.receive(new_id(_1)) }
    assert_violation(QUIC::ErrorCode::CONNECTION_ID_LIMIT_ERROR) { peer.receive(new_id(4)) }
  end

  # RFC 9000 "Detecting a Stateless Reset": the tokens of the IDs a
  # connection sends with, of those still active.
  def test_the_reset_tokens_of_the_ids_sent_with
    peer = ids
    (1..3).each { peer.receive(new_id(_1)) }
    assert_equal ["t".b * 16, new_id(2).stateless_reset_token], peer.reset_tokens(["\x00".b * 8, new_id(2).connection_id, "x".b * 8])
  end

  # A path besides the one in use claims an ID no path sends with, the
  # lowest first; given back, the ID is retired, and its token counts no
  # more. Zero-length IDs are the same for every path.
  def test_claim_and_release
    peer = ids
    (1..2).each { peer.receive(new_id(_1)) }
    assert_equal [new_id(1).connection_id, new_id(2).connection_id, nil], 3.times.map { peer.claim }
    peer.release(new_id(1).connection_id)
    peer.release(new_id(1).connection_id)
    assert_equal [1], retirements(peer)
    assert_empty peer.reset_tokens([new_id(1).connection_id])
    assert_equal "".b, ids(first: "".b).claim
  end

  # Retire Prior To retires the IDs below it, the one in use too, which
  # gives way to the lowest active.
  def test_retire_prior_to
    peer = ids
    peer.receive(new_id(1))
    peer.receive(new_id(2, retire_prior_to: 2))
    assert_equal new_id(2).connection_id, peer.current
    assert_equal [0, 1], retirements(peer)
    assert_equal [new_id(2).stateless_reset_token], peer.reset_tokens([peer.current])
  end

  # Retire Prior To retiring the ID in use, it gives way to the lowest no
  # path claimed; a path's ID retired is no longer claimed.
  def test_retire_prior_to_and_the_paths
    peer = ids
    (1..3).each { peer.receive(new_id(_1)) }
    assert_equal new_id(1).connection_id, peer.claim
    peer.receive(new_id(4, retire_prior_to: 2))
    assert_equal new_id(2).connection_id, peer.current
    refute peer.claimed?(new_id(1).connection_id)
  end

  # One that comes numbered below Retire Prior To goes straight back.
  def test_an_id_already_retired
    peer = ids
    peer.receive(new_id(3, retire_prior_to: 2))
    peer.receive(new_id(1))
    assert_equal [0, 1], retirements(peer)
    assert_equal new_id(3).connection_id, peer.current
  end

  def test_repeats
    peer = ids
    peer.receive(new_id(1))
    peer.receive(new_id(1))
    assert_violation(QUIC::ErrorCode::PROTOCOL_VIOLATION) { peer.receive(new_id(1, connection_id: "z".b * 8)) }
    assert_violation(QUIC::ErrorCode::PROTOCOL_VIOLATION) { peer.receive(new_id(2, connection_id: new_id(1).connection_id)) }
  end

  # A peer that sends with no connection ID issues none.
  def test_an_end_without_connection_ids
    assert_violation(QUIC::ErrorCode::PROTOCOL_VIOLATION) { ids(first: "".b).receive(new_id(1)) }
  end

  # A peer that retires IDs and acknowledges none of the retirements stops
  # past twice the limit (CVE-2026-84784); one that acknowledges them goes
  # on.
  def test_retirements_not_acknowledged
    peer = ids(limit: 2)
    assert_violation(QUIC::ErrorCode::CONNECTION_ID_LIMIT_ERROR) do
      (1..10).each do |sequence_number|
        peer.receive(new_id(sequence_number, retire_prior_to: sequence_number))
        retirements(peer)
      end
    end
    peer = ids(limit: 2)
    (1..10).each do |sequence_number|
      peer.receive(new_id(sequence_number, retire_prior_to: sequence_number))
      while (_, duty = peer.next_frame(100))
        peer.retire_acked(duty)
      end
    end
  end

  # A lost RETIRE_CONNECTION_ID goes again; an acknowledged one does not.
  def test_lost_retirements
    peer = ids
    peer.receive(new_id(1, retire_prior_to: 1))
    _, duty = peer.next_frame(100)
    peer.retire_lost(duty)
    assert_equal [0], retirements(peer)
    peer.retire_acked(duty)
    peer.retire_lost(duty)
    assert_empty retirements(peer)
  end
end
