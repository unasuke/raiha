# frozen_string_literal: true

module Raiha::Next::QUIC
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
      @max_datagram_size = max_datagram_size
      @tracer = tracer
      start_over
      @abandoned = false
      @ecn_state = :testing
      @ecn_testing_sent = 0
      @ecn_testing_lost = 0
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
      @challenge_due_at = now
      @challenge_interval = interval
      @validation_deadline = deadline
      @challenges_sent = {} #: Hash[String, bool]
    end

    # Whether the path is being validated.
    def validating? = !@validation_deadline.nil?

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
      @rtt = Recovery::RttEstimator.new
      cc = @config.congestion_control.new(max_datagram_size: @max_datagram_size, initial_window: @config.initial_window, config: @config,
        tracer: @tracer)
      @startup = @config.startup&.new(cc, max_datagram_size: @max_datagram_size, initial_window: @config.initial_window, tracer: @tracer)
      @congestion = @startup || cc
      @bytes_in_flight = 0
      @ack_eliciting_in_flight = 0
      @packets_in_flight = 0
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

    # The path's MTU changed (DPLPMTUD).
    def update_max_datagram_size(max_datagram_size, now:)
      @max_datagram_size = max_datagram_size
      @congestion.on_mtu_updated(max_datagram_size:, now:)
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

    private def change_ecn_state(state, now)
      return if state == @ecn_state
      @tracer.ecn_state_updated(old: @ecn_state, new: state, now:) if @tracer # steep:ignore
      @ecn_state = state
    end
  end
end
