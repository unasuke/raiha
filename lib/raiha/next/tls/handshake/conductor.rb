# frozen_string_literal: true

require_relative "../error"
require_relative "../event"
require_relative "../key_schedule"
require_relative "../keylog"
require_relative "../output"
require_relative "../trace"
require_relative "../transcript"
require_relative "key_update"
require_relative "reassembler"

module Raiha::Next::TLS
  module Handshake
    # The part of a handshake that does not depend on the role. It feeds the
    # peer's bytes through a Reassembler per epoch, the transcript and the
    # parser to the role's side (ClientSide or ServerSide), and collects what
    # comes out: the Output queue and the Event queue.
    #
    # Each kind of change has exactly one place, which a hygiene test checks:
    #
    # - `transition!` assigns the state;
    # - `change_epochs!` moves the read and write epochs and queues Secrets;
    # - `fail!` builds the Output::Alert;
    # - the transcript is added to only by the methods for receiving a
    #   message, sending one, and a ServerHello or HelloRetryRequest.
    #
    # Within one trigger, the Secrets that became usable go out before the
    # Messages; a failure drops the half-built flight and sends only the
    # alert. On failure, `discard!` or an exception from an object the user
    # gave (a Verifier or tracer), every secret is forgotten.
    class Conductor
      CERTIFICATE_MESSAGES = Set[Certificate::MSG_TYPE, CertificateRequest::MSG_TYPE, 25].freeze

      # The transcript hash before these messages is what their check covers.
      CHECKED_AGAINST_PREVIOUS_TRANSCRIPT = Set[CertificateVerify::MSG_TYPE, Finished::MSG_TYPE].freeze

      attr_reader :config, :keyring, :side, :state, :read_epoch, :write_epoch, :alert, :key_schedule

      # The side is built by the block, given this Conductor. `substitutions`
      # replace messages we send with given bytes, by message type and in
      # order; only Test::RFC8448 passes them.
      def initialize(config:, keyring:, tracer:, keylog: nil, substitutions: nil)
        @config = config
        @keyring = keyring
        @tracer = tracer
        @keylog = keylog
        @substitutions = substitutions&.transform_values(&:dup)
        @state = nil #: Symbol?
        @read_epoch = :initial #: epoch
        @write_epoch = :initial #: epoch
        @alert = nil #: Symbol?
        # @type var reassemblers: Hash[epoch, Reassembler]
        reassemblers = {}
        @reassemblers = reassemblers
        hashes = config.cipher_suites.map { |name| Config::CIPHER_SUITES_BY_NAME.fetch(name).hash_algorithm }.uniq
        @transcript = Transcript.new(hashes:)
        # What a trace shows before a hash is selected.
        @trace_hash = hashes.fetch(0)
        @key_schedule = nil #: KeySchedule?
        # @type var outputs: Array[Output::t]
        outputs = []
        @outputs = outputs
        # @type var events: Array[Event::t]
        events = []
        @events = events
        # @type var flight_secrets: Array[Output::Secret]
        flight_secrets = []
        @flight_secrets = flight_secrets
        # @type var flight_messages: Array[Output::Message]
        flight_messages = []
        @flight_messages = flight_messages
        @side = yield(self)
      end

      def failed? = @state == :failed

      # Runs the side's first steps (a client's ClientHello, a server's first
      # flight) as one trigger.
      def start(now:)
        guard { @side.start(now:) }
      end

      # Our own KeyUpdate, as one trigger: only once the handshake is
      # complete, and never with a Profile that has no KeyUpdate message.
      def request_key_update(request_peer_update:)
        raise UsageError, "this Profile has no KeyUpdate message" unless @config.profile.allow_key_update_message
        raise UsageError, "a KeyUpdate needs a complete handshake" unless @state == :connected
        guard { @side.request_key_update(request_peer_update:) }
      end

      # Application data is about to go out: a KeyUpdate owed goes first.
      def before_application_data
        guard { @side.before_application_data } if @state == :connected
        nil
      end

      def application_data_received
        @side.application_data_received if @state == :connected
        nil
      end

      def receive(bytes, epoch:, now:)
        guard do
          next if @state.nil? || failed?
          next fail!(:unexpected_message, :wrong_epoch) unless epoch == @read_epoch
          reassembler = reassembler_for(epoch)
          reassembler.expect(expected_types)
          status = reassembler << bytes
          status = drain(reassembler, epoch, now) if status == :ok
          reassembly_failed(status, reassembler) unless status == :ok || failed?
        end
      end

      # A message that did not come through `receive`, as a server's
      # ClientHello from an Acceptor does.
      def receive_message(epoch, raw, now:)
        guard { process(epoch, raw.getbyte(0).to_i, raw.byteslice(4, raw.bytesize).to_s, now) }
      end

      def each_output
        while (output = @outputs.shift)
          yield output
        end
      end

      def next_event = @events.shift

      # The message types acceptable now, from the side's table.
      def expected_types = @side.expected_types(@state, @read_epoch)

      # Whether bytes of the current epoch are waiting after the message
      # being handled.
      def pending_input? = reassembler_for(@read_epoch).pending?

      def transcript_hash = @transcript.digest

      # The key schedule of this handshake. Each traffic secret goes to the
      # keylog, if any, as it is derived.
      def start_key_schedule(hash:, client_random:, psk: nil)
        keylog = @keylog
        log = keylog && ->(name, secret) { keylog.write(Keylog.line(name, client_random, secret)) }
        @key_schedule = KeySchedule.new(hash:, psk:, on_traffic_secret: log)
      end

      def event!(event)
        @events << event
        nil
      end

      def tracing? = @tracer ? true : false

      def trace(value)
        @tracer&.tls_trace(value)
        nil
      end

      # The only assignment to the state. A state outside the side's STATES is
      # a bug here, not something the peer did, so it raises.
      def transition!(to)
        raise "#{to.inspect} is not a state of #{@side.class}" unless @side.class::STATES.include?(to) # steep:ignore
        @state = to
      end

      # The only place the epochs move and Secrets are queued. Moving the read
      # epoch with bytes of the old one still waiting means a handshake
      # message spans a key change: unexpected_message for RFC 9846, which
      # QUIC turns into PROTOCOL_VIOLATION (RFC 9001 "Sending and Receiving
      # Handshake Messages"). Returns false then. A KeyUpdate waiting there,
      # where the Profile takes none, fails as one: RFC 9001 "Key Update"
      # asks for unexpected_message for every KeyUpdate received.
      def change_epochs!(cipher_suite:, read: nil, write: nil, secrets: [])
        secrets.each do |epoch, direction, secret|
          @flight_secrets << Output::Secret.new(epoch:, direction:, secret:, cipher_suite:)
        end
        if read && read != @read_epoch
          if (left = @reassemblers[@read_epoch])&.pending?
            key_update = !@config.profile.allow_key_update_message && left.next_type == KeyUpdate::MSG_TYPE
            fail!(:unexpected_message, key_update ? @side.unexpected_reason(@state, KeyUpdate::MSG_TYPE) : :handshake_data_spans_key_change)
            return false
          end
          @read_epoch = read
        end
        @write_epoch = write if write
        true
      end

      # The only place an Output::Alert is built. Drops the flight being
      # built, queues the alert under the current write epoch and
      # Event::Failed, and forgets every secret.
      def fail!(alert, reason)
        return nil if failed?
        @flight_secrets.clear
        @flight_messages.clear
        @outputs << Output::Alert.new(level: :fatal, description: alert, epoch: @write_epoch)
        @events << Event::Failed.new(alert:, reason:)
        @alert = alert
        forget_secrets!
        transition!(:failed)
        nil
      end

      # The connection ended outside the handshake (a peer's alert, a QUIC
      # CONNECTION_CLOSE): forget everything and stop, without output.
      def discard!
        @flight_secrets.clear
        @flight_messages.clear
        forget_secrets!
        transition!(:failed) unless failed?
        nil
      end

      # Sends `message`: into the transcript and the flight. Returns the
      # message sent, which is a substitute's when one is queued for its type.
      def emit_message!(epoch, message)
        bytes, message = substitute(message)
        @transcript << bytes if Transcript::TRANSCRIPT_MESSAGES.include?(message.msg_type)
        trace_transcript(message.msg_type, bytes.bytesize)
        @flight_messages << Output::Message.new(epoch:, bytes: bytes.freeze)
        message
      end

      # A server's ServerHello: the suite is chosen, so the transcript keeps
      # only its hash from here.
      def emit_server_hello!(message, hash)
        @transcript.select!(hash)
        emit_message!(:initial, message)
      end

      # A client's ServerHello, added once the side has checked its suite.
      def record_server_hello!(raw, hash)
        @transcript << raw
        @transcript.select!(hash)
        trace_transcript(ServerHello::MSG_TYPE, raw.bytesize)
        nil
      end

      # A HelloRetryRequest the client received: ClientHello1 gives way to
      # message_hash under the HelloRetryRequest's hash (RFC 9846 "Transcript
      # Hash"), then the HelloRetryRequest follows.
      def receive_hello_retry_request!(raw, hash)
        @transcript.select!(hash)
        @transcript.restart_with_message_hash!
        @transcript << raw
        trace_transcript(ServerHello::MSG_TYPE, raw.bytesize)
        nil
      end

      # A HelloRetryRequest the server sends, in the same order.
      def emit_hello_retry_request!(message, hash)
        @transcript.select!(hash)
        @transcript.restart_with_message_hash!
        emit_message!(:initial, message)
      end

      # Ends the flight being built here, so that what follows goes out after
      # it. Only a KeyUpdate needs this: its Message goes under the old key,
      # before the Secret that replaces it.
      def close_flight!
        @outputs.concat(@flight_secrets)
        @outputs.concat(@flight_messages)
        @flight_secrets.clear
        @flight_messages.clear
        nil
      end

      # Runs a trigger: queues the flight it built, Secrets first. An
      # exception escaping it, from a user's object or a bug, leaves the
      # handshake failed with its secrets forgotten, and goes on up.
      private def guard
        yield
        close_flight!
      rescue StandardError
        discard!
        raise
      end

      private def drain(reassembler, epoch, now)
        reassembler.each_message do |msg_type, body|
          process(epoch, msg_type, body, now)
          break :ok if failed? || @read_epoch != epoch
          reassembler.expect(expected_types)
        end
      end

      # Bytes, then the transcript, then the parser, then the side. The
      # ServerHello waits for the side, which knows whether it is a
      # HelloRetryRequest only after checking it.
      private def process(epoch, msg_type, body, now)
        raw = [msg_type, body.bytesize >> 16, body.bytesize >> 8 & 0xff, body.bytesize & 0xff].pack("C4") + body
        before = @transcript.digest if CHECKED_AGAINST_PREVIOUS_TRANSCRIPT.include?(msg_type)
        if msg_type != ServerHello::MSG_TYPE && Transcript::TRANSCRIPT_MESSAGES.include?(msg_type)
          @transcript << raw
          trace_transcript(msg_type, raw.bytesize)
        end
        begin
          message = Handshake.parse_body(msg_type, body, registry: @config.registry)
        rescue Codec::Malformed => e
          return fail!(e.alert, :malformed_message)
        end
        if (violation = message.validate)
          return fail!(violation.alert, violation.reason)
        end
        @side.handle(message, raw:, transcript_hash_before: before, now:)
      end

      private def reassembly_failed(status, reassembler)
        if status == :overflow
          fail!(:decode_error, :message_too_large)
        else
          fail!(:unexpected_message, @side.unexpected_reason(@state, reassembler.next_type))
        end
      end

      private def reassembler_for(epoch)
        @reassemblers[epoch] ||= Reassembler.new(limits: ->(msg_type) { message_limit(msg_type) })
      end

      private def message_limit(msg_type)
        CERTIFICATE_MESSAGES.include?(msg_type) ? @config.max_certificate_message_size : @config.max_handshake_message_size
      end

      private def substitute(message) # steep:ignore
        bytes = @substitutions&.[](message.msg_type)&.shift
        return [message.encode, message] unless bytes
        [bytes, Handshake.parse(bytes, registry: @config.registry)]
      end

      private def trace_transcript(msg_type, length)
        tracer = @tracer or return
        digest = @transcript.digest(@transcript.selected || @trace_hash)
        tracer.tls_trace(Trace::TranscriptUpdated.new(msg_type:, length:, digest:))
      end

      private def forget_secrets!
        @key_schedule&.discard!
        @side.forget_secrets!
      end
    end
  end
end
