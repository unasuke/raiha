require "raiha/next/test_helper"
require "raiha/next/quic"

# The connection IDs this end issues: how many, in which frames, what goes
# again, and how the peer retires them.
class RaihaNextQUICIssuedConnectionIDsTest < Minitest::Test
  QUIC = Raiha::Next::QUIC

  # An issuer that makes IDs "00000001", "00000002" and so on, the token of
  # each its ID twice over, and remembers the connection it issued for and
  # the IDs it forgot.
  class Issuer
    attr_reader :connections, :forgotten

    def initialize
      @count = 0
      @connections = []
      @forgotten = []
    end

    def issue(connection)
      @connections << connection
      @count += 1
      id = format("%08d", @count).b
      [id, id * 2]
    end

    def forget(connection_id) = @forgotten << connection_id
  end

  def retire(sequence_number) = QUIC::Wire::Frame::RetireConnectionID.new(sequence_number:)

  # Four IDs issued, "0" * 8 the handshake's, and their issuer.
  def issued
    issuer = Issuer.new
    ids = QUIC::IssuedConnectionIDs.new("0".b * 8, issuer:, connection: :connection)
    ids.issue(4)
    frames(ids)
    [ids, issuer]
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
    assert_equal [[1, 0, "00000001", "00000001" * 2]], frames(ids).map { [_1.sequence_number, _1.retire_prior_to, _1.connection_id, _1.stateless_reset_token] }
    ids.issue(8)
    assert_equal [2, 3], frames(ids).map(&:sequence_number)
    assert_equal [:connection] * 3, issuer.connections
  end

  # A server's preferred address takes sequence number 1, with no frame,
  # and counts among those active: NEW_CONNECTION_ID frames go from 2.
  # Retired, it is replaced as any other.
  def test_the_preferred_address
    issuer = Issuer.new
    ids = QUIC::IssuedConnectionIDs.new("0".b * 8, issuer:, connection: :connection)
    preferred = ids.preferred_address({ ipv4: ["192.0.2.2", 4434] })
    assert_equal QUIC::TransportParameters::PreferredAddress.new(ipv4: ["192.0.2.2", 4434], ipv6: nil, connection_id: "00000001",
      stateless_reset_token: "00000001" * 2), preferred
    ids.issue(4)
    assert_equal [2, 3], frames(ids).map(&:sequence_number)
    ids.lost(QUIC::Recovery::Duty::NewConnectionID.new(sequence_number: 1))
    assert_empty frames(ids)
    ids.retire(retire(1), dcid: "0".b * 8, forget_at: 1.0)
    assert_equal [4], frames(ids).map(&:sequence_number)
  end

  # No address, zero-length connection IDs or no issuer: no preferred
  # address.
  def test_no_preferred_address
    issuer = Issuer.new
    assert_nil QUIC::IssuedConnectionIDs.new("0".b * 8, issuer:, connection: :connection).preferred_address(nil)
    assert_nil QUIC::IssuedConnectionIDs.new("".b, issuer:, connection: :connection).preferred_address({ ipv4: ["192.0.2.2", 4434] })
    assert_nil QUIC::IssuedConnectionIDs.new("0".b * 8, issuer: nil, connection: :connection).preferred_address({ ipv4: ["192.0.2.2", 4434] })
    assert_empty issuer.connections
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

  # An ID the peer retires is replaced by a new one, and forgotten when
  # its time comes; one retired again is nothing.
  def test_retire_and_replace
    ids, issuer = issued
    ids.retire(retire(2), dcid: "0".b * 8, forget_at: 3.0)
    ids.retire(retire(2), dcid: "0".b * 8, forget_at: 4.0)
    assert_equal [[4, "00000004"]], frames(ids).map { [_1.sequence_number, _1.connection_id] }
    assert_equal 3.0, ids.next_timeout
    ids.handle_timeout(2.9)
    assert_empty issuer.forgotten
    ids.handle_timeout(3.0)
    assert_equal ["00000002"], issuer.forgotten
    assert_nil ids.next_timeout
  end

  # A sequence number never issued, or that of the packet's own ID, is
  # PROTOCOL_VIOLATION (RFC 9000 "RETIRE_CONNECTION_ID Frames").
  def test_retire_what_cannot_be
    ids, = issued
    [[4, "0".b * 8], [1, "00000001"]].each do |sequence_number, dcid|
      error = assert_raises(QUIC::Violation) { ids.retire(retire(sequence_number), dcid:, forget_at: 1.0) }
      assert_equal [QUIC::ErrorCode::PROTOCOL_VIOLATION, 0x19], [error.code, error.frame_type]
    end
  end

  # An ID retired before its NEW_CONNECTION_ID went does not go.
  def test_retired_before_it_went
    issuer = Issuer.new
    ids = QUIC::IssuedConnectionIDs.new("0".b * 8, issuer:, connection: :connection)
    ids.issue(2)
    ids.retire(retire(1), dcid: "0".b * 8, forget_at: 1.0)
    assert_equal [2], frames(ids).map(&:sequence_number)
  end

  # Past MAX_RETIRED waiting, the oldest are forgotten at once.
  def test_retired_wait_to_a_bound
    ids, issuer = issued
    20.times { |i| ids.retire(retire(i < 3 ? i + 1 : i + 2), dcid: "0".b * 8, forget_at: 10.0) }
    assert_equal 20 - QUIC::IssuedConnectionIDs::MAX_RETIRED, issuer.forgotten.size
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
