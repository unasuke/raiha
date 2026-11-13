# frozen_string_literal: true

module Raiha::QUIC
  # One path of a connection, with what loss recovery keeps for it: the RTT,
  # the congestion controller made from the Config, the bytes and
  # ack-eliciting packets in flight on it, and its Pacer, whose bucket
  # holds RFC 9002's initial window whatever the Config's is, or what the
  # pacing rate gives in one granularity when that is more, and its
  # RateMeter. A new path starts them all over (RFC 9000 "Connection
  # Migration"); packets sent on a path that is gone count for nothing.
  #
  # A path goes between a local and a remote address, and keeps what came
  # on it and what went until the remote address is validated, which the
  # amplification limit goes by (RFC 9000 "Address Validation").
  class Path
    # RFC 9000 "Address Validation": an endpoint sends no more than three
    # times what it received to an address not validated.
    AMPLIFICATION_FACTOR = 3
    # RFC 9000 "Datagram Size": the least every path carries.
    MIN_DATAGRAM_SIZE = 1200
    # PTOs in a row with no ACK that may be a black hole: from the first,
    # as long as persistent congestion takes, three PTOs.
    BLACK_HOLE_PTOS = 2

    attr_reader :rtt
    attr_reader :bytes_in_flight
    attr_reader :ack_eliciting_in_flight
    attr_reader :packets_in_flight
    attr_reader :max_datagram_size

    # The addresses the path goes between, [host, port] each; nil while not
    # known yet.
    attr_reader :local
    attr_reader :remote

    def initialize(config:, local: nil, remote: nil, validated: false, destination_connection_id: nil,
      max_datagram_size: config.initial_max_datagram_size, tracer: nil)
      @config = config
      @local = local
      @remote = remote
      @validated = validated
      @received_unvalidated = 0
      @sent_unvalidated = 0
      @challenge = nil #: String?
      @destination_connection_id = destination_connection_id
      @challenge_due_at = nil #: Float?
      @challenge_interval = nil #: Float?
      @validation_deadline = nil #: Float?
      @challenges_sent = {} #: Hash[String, bool]
      @full_size_due = false
      @validation_owed = false
      @max_datagram_size = max_datagram_size
      @mtu_search = nil #: MTUSearch?
      @tracer = tracer
      start_over
      @abandoned = false
      @ecn_state = :testing
      @ecn_testing_sent = 0
      @ecn_testing_lost = 0
      # PTOs in a row with nothing of the path's acknowledged.
      @timed_out = 0
    end

    # The addresses a datagram that came on the path names, `local` the one
    # it came to and `remote` the one it came from, fill in those the path
    # does not know yet: a server learns both from the client's first
    # Initial, a client its own from the first datagram it takes.
    def learn(local:, remote:)
      @local ||= local
      @remote ||= remote
    end

    # Whether the remote address is validated: a client's is from the
    # start, a server's once the client shows it receives there.
    def validated? = @validated

    # The remote address is validated: the amplification limit is off.
    def validate = @validated = true

    # A datagram of `bytes` came on the path, which counts until the
    # address is validated, each datagram once.
    def datagram_received(bytes)
      @received_unvalidated += bytes unless @validated
    end

    # A datagram of `bytes` went on the path.
    def datagram_sent(bytes)
      @sent_unvalidated += bytes unless @validated
    end

    # How many bytes may go on the path before the address is validated;
    # nil once it is.
    def amplification_budget = @validated ? nil : AMPLIFICATION_FACTOR * @received_unvalidated - @sent_unvalidated

    # A PATH_CHALLENGE with `data` came on the path. Only the last waits
    # for an answer, a newer taking the place of one not answered yet, so
    # that a peer that sends many piles up nothing (CVE-2023-49295,
    # CVE-2023-6193).
    def challenged(data) = @challenge = data

    # The data of the challenge waiting for an answer; nil when none does.
    attr_reader :challenge

    # The challenge is answered: each is, once.
    def answered = @challenge = nil

    # The peer's connection ID this end sends with on the path, when it is
    # not the one in use; nil on the path in use, whose ID the connection
    # keeps.
    attr_reader :destination_connection_id

    # The path, left by the connection, sends with `connection_id`; nil
    # when it has none to send with.
    def send_with(connection_id) = @destination_connection_id = connection_id

    # Validation of the path starts at `now` (RFC 9000 "Path Validation"):
    # a PATH_CHALLENGE goes at once and again each `interval`, twice as
    # long each time, until `deadline`, when the path fails.
    def start_validation(now:, interval:, deadline:)
      @validation_owed = false
      @challenge_due_at = now
      @challenge_interval = interval
      @validation_deadline = deadline
      @challenges_sent = {} #: Hash[String, bool]
    end

    # Whether the path is being validated.
    def validating? = !@validation_deadline.nil?

    # The validation stops where it is, neither failing nor succeeding, and
    # is owed: the path is to be validated anew before it is used again.
    def stop_validation
      @challenge_due_at = @challenge_interval = @validation_deadline = nil
      @challenges_sent = {}
      @full_size_due = false
      @validation_owed = true
    end

    # Whether a validation stopped is owed.
    def validation_owed? = @validation_owed

    # Whether a PATH_CHALLENGE is due on the path at `now`.
    def challenge_due?(now)
      due = @challenge_due_at
      !due.nil? && due <= now
    end

    # A PATH_CHALLENGE with `data` went at `now` in a datagram that was
    # `full_size` (MIN_INITIAL_DATAGRAM bytes or more) or not; the next is
    # due an interval on, the interval doubled (RFC 9002 "Computing PTO").
    def challenge_sent(data, full_size:, now:)
      interval = @challenge_interval or return
      @challenges_sent[data] = full_size
      @challenge_due_at = now + interval
      @challenge_interval = interval * 2
    end

    # A PATH_RESPONSE with `data` came: whether it answers a challenge sent
    # on the path. The answer to one in a full-size datagram ends the
    # validation; to a smaller one, it validates the address, and the
    # next challenge, due at once, is to go in a full-size datagram
    # (RFC 9000 "Initiating Path Validation").
    def responded(data, now:)
      full_size = @challenges_sent.fetch(data) { return false }
      validate
      if full_size
        @challenge_due_at = @challenge_interval = @validation_deadline = nil
        @full_size_due = false
        @challenges_sent = {}
      else
        @full_size_due = true
        @challenge_due_at = now
      end
      true
    end

    # Whether the next challenge must go in a full-size datagram, the
    # address validated by an answer to a smaller one.
    def full_size_due? = @full_size_due

    # When something of the validation is due: the next challenge, or the
    # deadline.
    def validation_timeout = [@challenge_due_at, @validation_deadline].compact.min

    # When the validation fails unless answered first; nil when there is
    # none.
    attr_reader :validation_deadline

    # Whether the validation has failed by `now`.
    def validation_failed?(now)
      deadline = @validation_deadline
      !deadline.nil? && deadline <= now
    end

    # Takes the RTT, the congestion controller and the counts in flight back
    # to where a new path starts, as after a Retry (RFC 9002 "Handling Retry
    # Packets").
    def start_over
      @bytes_in_flight = 0
      @ack_eliciting_in_flight = 0
      @packets_in_flight = 0
      start_learning
    end

    # The path takes over what `path`, which only the peer's port tells
    # apart, learned of the network: its RTT, congestion controller,
    # pacer, rate meter, datagram size, the search for it, and ECN state
    # (RFC 9000 "Loss Detection and Congestion Control", a NAT rebinding
    # most likely). `path` starts learning over, so that what was sent on
    # it counts for nothing here, and keeps what it has in flight.
    def take_over(path) = path.hand_over_to(self)

    # Gives `path` what this path learned, and starts learning over. A
    # probe of the MTU out on this path is heard of here, where the search
    # no longer is, so the search sends the next on `path`.
    def hand_over_to(path)
      @mtu_search&.abandon_probe
      path.adopt(rtt: @rtt, congestion: @congestion, startup: @startup, pacer: @pacer, rate_meter: @rate_meter, rtt_heard: @rtt_heard,
        max_datagram_size: @max_datagram_size, mtu_search: @mtu_search, ecn: [@ecn_state, @ecn_testing_sent, @ecn_testing_lost])
      @mtu_search = nil
      @ecn_state = :testing
      @ecn_testing_sent = @ecn_testing_lost = 0
      start_learning
    end

    # Takes what another path learned (hand_over_to).
    def adopt(rtt:, congestion:, startup:, pacer:, rate_meter:, rtt_heard:, max_datagram_size:, mtu_search:, ecn:)
      @rtt = rtt
      @congestion = congestion
      @startup = startup
      @pacer = pacer
      @rate_meter = rate_meter
      @rtt_heard = rtt_heard
      @max_datagram_size = max_datagram_size
      @mtu_search = mtu_search
      @ecn_state, @ecn_testing_sent, @ecn_testing_lost = ecn
    end

    # A new RTT estimator, congestion controller, pacer and rate meter.
    private def start_learning
      @rtt = Recovery::RttEstimator.new
      cc = @config.congestion_control.new(max_datagram_size: @max_datagram_size, initial_window: @config.initial_window, config: @config,
        tracer: @tracer)
      @startup = @config.startup&.new(cc, max_datagram_size: @max_datagram_size, initial_window: @config.initial_window, tracer: @tracer)
      @congestion = @startup || cc
      @app_limited = false
      @rtt_heard = false
      @pacer = Pacer.new(capacity: Config::DEFAULT_INITIAL_WINDOW.call(@max_datagram_size), granularity: @config.pacing_granularity)
      @pacing_release_at = nil #: Float?
      @rate_meter = Recovery::RateMeter.new
    end

    # The congestion controller, or the Config's startup wrapping it until
    # the startup is done: then the path takes the controller back, so that
    # what comes after goes to it with nothing in between.
    def congestion
      startup = @startup
      if startup&.done?
        @congestion = startup.handover
        @startup = nil
      end
      @congestion
    end

    # :testing, :capable or :failed (loss recovery's design, "Marking").
    attr_reader :ecn_state

    # The codepoint to mark packets with: ECT(0) until the path fails.
    def ecn = @ecn_state == :failed ? :not_ect : :ect0

    # A packet marked ECT(0) was sent.
    def ecn_sent
      @ecn_testing_sent += 1 if @ecn_state == :testing
    end

    # ECT(0) packets were declared lost: while testing, all of them lost
    # fails the path (RFC 9000 "ECN Validation").
    def ecn_lost(count, now:)
      return unless @ecn_state == :testing
      @ecn_testing_lost += count
      ecn_failed(now:) if @ecn_testing_lost >= @ecn_testing_sent
    end

    # An ACK of ECT(0) packets passed validation.
    def ecn_validated(now:)
      change_ecn_state(:capable, now) if @ecn_state == :testing
    end

    # The path fails ECN for good: no marks and no counts heeded.
    def ecn_failed(now:)
      change_ecn_state(:failed, now)
    end

    # Counts a packet that went in flight on this path, and tells the
    # congestion controller.
    def add_in_flight(sent_bytes:, ack_eliciting:, now:)
      @bytes_in_flight += sent_bytes
      @packets_in_flight += 1
      @ack_eliciting_in_flight += 1 if ack_eliciting
      @pacer.sent(sent_bytes)
      @congestion.on_packet_sent(bytes: sent_bytes, now:)
    end

    # Whether pacing lets a datagram of `size` bytes go in flight now, at
    # the congestion controller's rate; when it does not, `pacing_release_at`
    # is when it will.
    def paced?(size, now)
      @pacing_release_at = @pacer.release_at(size, @congestion.pacing_rate, now)
      @pacing_release_at.nil?
    end

    # When pacing lets what is held back go, while sending is stopped for
    # it.
    attr_reader :pacing_release_at

    # Bytes in flight of Application Data on this path were acknowledged at
    # `now`, the largest packet newly acknowledged numbered `largest`.
    def delivered(bytes, largest:, now:) = @rate_meter.on_ack(bytes, largest:, now:)

    # The rate the path delivers at by its RateMeter, bytes a second; nil
    # before a sample.
    def delivery_rate = @rate_meter.rate

    # Packets of `acked_bytes` in flight on this path were acknowledged,
    # the latest of them sent at `largest_acked_sent_at`; the congestion
    # controller hears of them with the path's RTT, and with its latest
    # sample when the ACK's was the path's, `sampled`.
    def acked(acked_bytes:, largest_acked_sent_at:, sampled:, now:)
      @timed_out = 0
      rtt = @rtt
      min_rtt = rtt.min_rtt
      @rtt_heard = true if min_rtt
      congestion.on_ack(acked_bytes:, largest_acked_sent_at:, latest_rtt: (rtt.latest_rtt if sampled), smoothed_rtt: rtt.smoothed_rtt,
        min_rtt:, app_limited: @app_limited, now:)
    end

    # No longer counts a packet acknowledged, lost or discarded.
    def remove_in_flight(sent_bytes:, ack_eliciting:)
      @bytes_in_flight -= sent_bytes
      @packets_in_flight -= 1
      @ack_eliciting_in_flight -= 1 if ack_eliciting
    end

    # Whether the window went unused when sending last stopped, which keeps
    # the congestion controller from growing it (RFC 9002 "Underutilizing
    # the Congestion Window"). false until the first stop.
    def app_limited? = @app_limited

    # Sending stopped, for `reason`: :drained (nothing left to send),
    # :flow_control, :amplification (the server's limit before the client's
    # address is validated), :congestion (the window is full) or :pacing.
    # Only the window filled up, or pacing holding back what would have
    # filled it, leaves the window used; pacing with no stream data or
    # DATAGRAMs `waiting` holds back nothing, and is as nothing left to
    # send. With them waiting and the window or pacing holding them back,
    # the rate meter counts what goes from `next_packet_number`, the least
    # the next 1-RTT packet will be numbered.
    def transmission_stopped(reason, waiting:, next_packet_number:)
      @pacing_release_at = nil unless reason == :pacing
      @rate_meter.sending_stopped(limited: waiting && (reason == :congestion || reason == :pacing), next_packet_number:)
      @app_limited = case reason
        when :drained then @bytes_in_flight < window
        when :pacing then !waiting && @bytes_in_flight < window
        when :flow_control, :amplification then true
        when :congestion then false
        else raise ArgumentError, "unknown reason to stop sending: #{reason.inspect}"
        end
    end

    # The path's MTU changed (DPLPMTUD): the congestion controller hears,
    # and the pacer's burst is RFC 9002's initial window of the new size.
    def update_max_datagram_size(max_datagram_size, now:)
      old = @max_datagram_size
      @max_datagram_size = max_datagram_size
      @congestion.on_mtu_updated(max_datagram_size:, now:)
      @pacer.capacity = Config::DEFAULT_INITIAL_WINDOW.call(max_datagram_size)
      @tracer.mtu_updated(old:, new: max_datagram_size, done: @mtu_search&.done? || false, now:) if @tracer # steep:ignore
    end

    # The path searches for the largest datagram it carries, up to `up_to`
    # bytes, from what it carries now (MTUSearch); a search under way or
    # done goes on as it is.
    def search_mtu(up_to:)
      @mtu_search ||= MTUSearch.new(from: @max_datagram_size, up_to:)
    end

    # The size of the probe of the path's MTU to send next; nil when none
    # is due.
    def mtu_probe_size = @mtu_search&.next_size

    # A probe of `size` bytes went on the path.
    def mtu_probe_sent(size) = @mtu_search&.sent(size)

    # A probe of `size` bytes got through: the path carries datagrams that
    # large from now on, when they are larger than before.
    def mtu_probe_acked(size, now:)
      through = @mtu_search&.acked(size) or return
      update_max_datagram_size(through, now:)
    end

    # A probe of `size` bytes was lost at `now`, which may end the search.
    def mtu_probe_lost(size, now:)
      search = @mtu_search or return
      done = search.done?
      search.lost(size)
      return if done || !search.done?
      @tracer.mtu_updated(old: @max_datagram_size, new: @max_datagram_size, done: true, now:) if @tracer # steep:ignore
    end

    # Persistent congestion on the path, which may be a black hole.
    def persistent_congestion(now:) = black_hole(now)

    # A PTO ran out while the path was in use: BLACK_HOLE_PTOS in a row,
    # with nothing of the path's acknowledged in between, may be a black
    # hole, which persistent congestion, judged on an ACK, never tells of
    # when nothing at all gets through. Those that ran out on another path
    # before the connection moved here count for nothing.
    def probe_timed_out(now:)
      @timed_out += 1
      black_hole(now) if @timed_out >= BLACK_HOLE_PTOS
    end

    # The window sending goes by: the congestion controller's, but until
    # an ACK tells the controller an RTT, when nothing is paced, no more
    # than RFC 9002's initial window, however large the Config's, as RFC
    # 9002 "Pacing" keeps a burst to it. A Retry's RTT sample tells the
    # controller nothing.
    def window
      window = @congestion.window
      return window if @rtt_heard
      [window, Config::DEFAULT_INITIAL_WINDOW.call(@max_datagram_size)].min
    end

    # The congestion window in datagrams.
    def window_packets = @congestion.window / @max_datagram_size

    # The connection left this path; what was sent on it no longer counts.
    def abandon = @abandoned = true

    def abandoned? = @abandoned

    # On a path that carries more than MIN_DATAGRAM_SIZE, the larger
    # datagrams may be lost in a black hole (RFC 9000 "Datagram Size"): the
    # path goes back to MIN_DATAGRAM_SIZE, and its search starts over.
    private def black_hole(now)
      return unless @max_datagram_size > MIN_DATAGRAM_SIZE
      @mtu_search = nil
      update_max_datagram_size(MIN_DATAGRAM_SIZE, now:)
    end

    private def change_ecn_state(state, now)
      return if state == @ecn_state
      @tracer.ecn_state_updated(old: @ecn_state, new: state, now:) if @tracer # steep:ignore
      @ecn_state = state
    end
  end
end
