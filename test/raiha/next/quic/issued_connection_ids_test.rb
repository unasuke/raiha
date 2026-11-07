require "raiha/next/test_helper"
require "raiha/next/quic"

# The connection IDs this end issues: how many, in which frames, and what
# goes again.
class RaihaNextQUICIssuedConnectionIDsTest < Minitest::Test
  QUIC = Raiha::Next::QUIC

  # An issuer that makes IDs "1" * 8, "2" * 8 and so on, the token of each
  # its ID twice over, and remembers the connection it issued for.
  class Issuer
    attr_reader :connections

    def initialize
      @count = 0
      @connections = []
    end

    def issue(connection)
      @connections << connection
      @count += 1
      id = @count.to_s.b * 8
      [id, id * 2]
    end
  end

  def frames(ids)
    out = []
    while (frame, = ids.next_frame(100))
      out << frame
    end
    out
  end

  # As many as the peer's limit takes, MAX at most, sequence number 0
  # among them, each in a NEW_CONNECTION_ID frame retiring nothing.
  def test_up_to_the_peer_s_limit_and_max
    issuer = Issuer.new
    ids = QUIC::IssuedConnectionIDs.new("0".b * 8, issuer:, connection: :connection)
    ids.issue(2)
    assert_equal [[1, 0, "1".b * 8, "1".b * 16]], frames(ids).map { [_1.sequence_number, _1.retire_prior_to, _1.connection_id, _1.stateless_reset_token] }
    ids.issue(8)
    assert_equal [2, 3], frames(ids).map(&:sequence_number)
    assert_equal [:connection] * 3, issuer.connections
  end

  def test_a_lost_frame_goes_again_as_it_was
    ids = QUIC::IssuedConnectionIDs.new("0".b * 8, issuer: Issuer.new, connection: :connection)
    ids.issue(4)
    sent = frames(ids)
    ids.lost(QUIC::Recovery::Duty::NewConnectionID.new(sequence_number: 2))
    ids.lost(QUIC::Recovery::Duty::NewConnectionID.new(sequence_number: 2))
    assert_equal [sent[1]], frames(ids)
  end

  def test_a_frame_waits_for_room
    ids = QUIC::IssuedConnectionIDs.new("0".b * 8, issuer: Issuer.new, connection: :connection)
    ids.issue(2)
    assert_nil ids.next_frame(10)
    refute_nil ids.next_frame(100)
  end

  # With zero-length connection IDs, or no issuer, none is issued.
  def test_none_issued
    issuer = Issuer.new
    [QUIC::IssuedConnectionIDs.new("".b, issuer:, connection: :connection),
     QUIC::IssuedConnectionIDs.new("0".b * 8, issuer: nil, connection: :connection)].each do |ids|
      ids.issue(4)
      assert_empty frames(ids)
    end
    assert_empty issuer.connections
  end
end
