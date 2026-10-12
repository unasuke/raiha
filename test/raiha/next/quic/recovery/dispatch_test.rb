require "raiha/next/test_helper"
require "raiha/next/support/quic_recovery"

# Loss recovery's design, "Duties": the acknowledged and lost packets
# handed back are told to the owner of what they carried, one branch for
# each kind of duty.
class RaihaNextQUICRecoveryDispatchTest < Minitest::Test
  include NextQUICRecovery

  Duty = QUIC::Recovery::Duty
  Outcome = QUIC::Recovery::Outcome

  # An owner that keeps every call as [name, *arguments].
  class RecordingOwner
    attr_reader :calls

    def initialize = @calls = []

    def method_missing(name, *arguments) = @calls << [name, *arguments]

    def respond_to_missing?(*) = true
  end

  # What the owner hears of each kind when acknowledged and when lost, as
  # the table of duties says; nil for nothing.
  CALLS = {
    Duty::Stream => %i[stream_data_acked stream_data_lost],
    Duty::Crypto => %i[crypto_data_acked crypto_data_lost],
    Duty::Ack => [:ack_frame_acked, nil],
    Duty::ResetStream => %i[reset_stream_acked reset_stream_lost],
    Duty::StopSending => [nil, :stop_sending_lost],
    Duty::MaxData => [nil, :max_data_lost],
    Duty::MaxStreamData => [nil, :max_stream_data_lost],
    Duty::MaxStreams => [nil, :max_streams_lost],
    Duty::DataBlocked => [nil, :data_blocked_lost],
    Duty::StreamDataBlocked => [nil, :stream_data_blocked_lost],
    Duty::StreamsBlocked => [nil, :streams_blocked_lost],
    Duty::NewConnectionID => [nil, :new_connection_id_lost],
    Duty::RetireConnectionID => [nil, :retire_connection_id_lost],
    Duty::NewToken => [nil, :new_token_lost],
    Duty::HandshakeDone => [nil, :handshake_done_lost]
  }.freeze

  def packet(*duties)
    QUIC::Recovery::SentPacket.new(packet_number: 0, time_sent: 0.0, sent_bytes: 1200, ack_eliciting: true, in_flight: true,
      path: QUIC::Path.new(config: QUIC::Config.new), duties: duties.freeze, pmtu_probe: false, ecn: :not_ect)
  end

  def dispatch(acked: [], lost: [])
    owner = RecordingOwner.new
    Duty.dispatch(Outcome.new(acked:, lost:, probe: nil), to: owner)
    owner.calls
  end

  # Every kind has a branch both ways. HandshakeDone carries nothing, so
  # its owner is told nothing more than the name.
  def test_every_kind_has_a_branch
    assert_equal Duty::ALL, CALLS.keys
    CALLS.each do |kind, (acked, lost)|
      duty = kind.new(**kind.members.to_h { [_1, 0] })
      assert_equal acked ? [[acked, duty]] : [], dispatch(acked: [packet(duty)]), kind
      expected = lost && (kind == Duty::HandshakeDone ? [[lost]] : [[lost, duty]])
      assert_equal expected || [], dispatch(lost: [packet(duty)]), kind
    end
  end

  # There is no else: a kind without its branch raises.
  def test_a_kind_without_a_branch_raises
    assert_raises(NoMatchingPatternError) { dispatch(acked: [packet(Object.new)]) }
    assert_raises(NoMatchingPatternError) { dispatch(lost: [packet(Object.new)]) }
  end

  # The acknowledged first, then the lost, each packet's duties in order.
  def test_the_acknowledged_first
    stream = Duty::Stream.new(stream_id: 0, offset: 0, length: 100, fin: false)
    crypto = Duty::Crypto.new(space: :handshake, offset: 0, length: 100)
    ack = Duty::Ack.new(space: :handshake, largest: 7)
    calls = dispatch(acked: [packet(crypto), packet(ack, stream)], lost: [packet(stream, crypto)])
    assert_equal [[:crypto_data_acked, crypto], [:ack_frame_acked, ack], [:stream_data_acked, stream],
      [:stream_data_lost, stream], [:crypto_data_lost, crypto]], calls
  end

  # What one ACK hands back, as Recovery gives it.
  def test_an_outcome_of_an_ack
    recovery = recovery()
    duties = Array.new(5) { Duty::Crypto.new(space: :handshake, offset: _1 * 100, length: 100) }
    duties.each { send_packet(recovery, :handshake, now: 0.0, duties: [_1]) }
    owner = RecordingOwner.new
    Duty.dispatch(recovery.on_ack_received(packet_type: :handshake, ack: ack(4..4), now: 0.05), to: owner)
    assert_equal [[:crypto_data_acked, duties[4]], [:crypto_data_lost, duties[0]], [:crypto_data_lost, duties[1]]], owner.calls
  end
end
