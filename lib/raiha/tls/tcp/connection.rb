# frozen_string_literal: true

require_relative "../error"
require_relative "../event"
require_relative "../iana"
require_relative "../output"
require_relative "../record"
require_relative "../trace"
require_relative "../handshake/machine"
require_relative "event"

module Raiha::TLS
  module TCP
    # TLS over TCP without I/O: a handshake Machine and a Record::Layer put
    # together. Bytes read from the socket go into `receive`; the bytes to
    # write come out of `each_output`. The application's data goes in by
    # `write` and comes out of `read`.
    #
    # Bytes from the peer never raise: a failure sends an alert, if there is
    # one to send, and shows as an event. Writing to or reading from a
    # connection that failed raises UsageError.
    class Connection
      # How much of the application's data `write` holds before it goes out:
      # held until the handshake completes, then until `each_output` takes
      # it. Past this `write` takes less, or nothing.
      WRITE_BUFFER_LIMIT = 64 * 1024

      ALERT_LEVELS = { warning: 1, fatal: 2 }.freeze #: Hash[Symbol, Integer]

      # user_canceled alerts read on in a row, without application data
      # between them; one more ends the connection. BoringSSL's
      # kMaxWarningAlerts, which rustls uses too.
      MAX_CONSECUTIVE_WARNING_ALERTS = 4

      # Event::NewSessionTickets held until taken: one past this drops the
      # oldest, so that a server sending tickets without end cannot make a
      # client keep them all.
      MAX_HELD_TICKETS = 8

      # A client resumes `session` if it still may (Machine.client), and
      # with `early_data: true` sends 0-RTT through `write_early_data` when it
      # can.
      def self.client(config:, keyring:, server_name:, now:, extensions: [], tracer: nil, keylog: nil, session: nil, early_data: false)
        machine = Handshake::Machine.client(config:, keyring:, server_name:, now:, extensions:, tracer:, keylog:, session:, early_data:)
        new(machine, config, early_data_room: session&.max_early_data_size || 0, tracer:)
      end

      # A server takes its ClientHello through `receive`, or from an
      # Acceptor that has offered one: then with the bytes that came after it,
      # read before anything given to `receive`. `anti_replay` is the record
      # of the 0-RTT taken (Machine.server), which a Config that takes 0-RTT
      # needs.
      def self.server(config:, keyring:, now:, acceptor: nil, extensions: [], tracer: nil, keylog: nil, anti_replay: nil)
        raise ArgumentError, "a TCP::Connection needs a profile with a record layer, as Profile::TCP" unless config.profile.record_layer
        unless acceptor
          return new(Handshake::Machine.server(config:, keyring:, now:, extensions:, tracer:, keylog:, anti_replay:), config, tracer:)
        end
        accepted, record = acceptor.hand_over
        machine = Handshake::Machine.server(config:, keyring:, client_hello: accepted, now:, extensions:, tracer:, keylog:, anti_replay:)
        new(machine, config, record:, client_hello_received: true, tracer:).tap { |connection| connection.receive("".b, now:) }
      end

      private_class_method :new

      def initialize(machine, config, record: Record::Layer.new(profile: config.profile), client_hello_received: false, early_data_room: 0,
        tracer: nil)
        @machine = machine
        @config = config
        @tracer = tracer
        @record = record
        # How much more 0-RTT the session lets a client send.
        @early_data_room = early_data_room
        @outgoing = "".b
        @unsent = "".b
        @received = "".b
        # The client's 0-RTT a server took, until read, and how much came.
        @early_received = "".b
        @early_data_size = 0
        # @type var events: Array[event]
        events = []
        @events = events
        @failed = false
        @read_closed = false
        @write_closed = false
        @consecutive_warning_alerts = 0
        @handshake_received = client_hello_received
        @record_size_limits_set = false
        @change_cipher_spec_sent = !config.profile.compatibility_mode
        limit_record_sizes
        drain_machine
      end

      # Bytes read from the socket, in any pieces. After the peer's
      # close_notify they are ignored.
      def receive(bytes, now:)
        return nil if @failed || @read_closed
        @record << bytes
        until @failed || @read_closed || (record = @record.read(epoch: @machine.read_epoch, skip_early_data: @machine.skip_early_data_limit)).nil?
          case record
          when Record::Failure then fail!(record.alert, record.reason)
          else take(record, now)
          end
        end
        nil
      end

      # The bytes to write to the socket, if any.
      def each_output
        return if @outgoing.empty?
        bytes = @outgoing
        @outgoing = "".b
        yield bytes
      end

      # Takes as much of `data` as fits WRITE_BUFFER_LIMIT and returns how
      # much that was. Before the handshake completes it is held, and sent
      # as 1-RTT data once it does.
      def write(data)
        raise UsageError, "the connection failed" if @failed
        raise UsageError, "our side is closed" if @write_closed
        room = WRITE_BUFFER_LIMIT - @unsent.bytesize - @outgoing.bytesize
        taken = data.byteslice(0, room.clamp(0..)).to_s # steep:ignore
        @unsent << taken
        send_application_data
        taken.bytesize
      end

      # Sends as much of `data` as 0-RTT as the session allows and returns how
      # much that was, or nil when 0-RTT is over or never began: a client
      # given `early_data: true` sends it from the start until the server
      # takes it or not (RFC 9846 "Early Data Indication"). 0-RTT the server
      # did not take is not sent again (Event::EarlyDataRejected), and may
      # be replayed: send in it only what may be.
      def write_early_data(data)
        raise UsageError, "the connection failed" if @failed
        raise UsageError, "our side is closed" if @write_closed
        return nil unless @machine.write_epoch == :early_data
        taken = data.byteslice(0, @early_data_room).to_s
        @early_data_room -= taken.bytesize
        send_record(:application_data, taken, :early_data) unless taken.empty?
        taken.bytesize
      end

      # Up to `max_bytes` of the peer's application data, "" when none has
      # come, and nil once the peer has closed its side and all is read. The
      # client's 0-RTT is read first, by `read_early_data`.
      def read(max_bytes)
        raise UsageError, "0-RTT is left to read_early_data" unless @early_received.empty?
        return nil if @read_closed && @received.empty?
        raise UsageError, "the connection failed" if @failed && @received.empty?
        @received.slice!(0, max_bytes).to_s
      end

      # Up to `max_bytes` of the client's 0-RTT that a server took, "" when
      # none has come yet, and nil once it is over (EndOfEarlyData came and
      # all is read) or there is none, not offered or not taken. It may be a
      # replay of another connection's (RFC 9846 "Replay Attacks on 0-RTT"):
      # `handshake_complete?` says when the client has proved it is live.
      def read_early_data(max_bytes)
        raise UsageError, "the connection failed" if @failed && @early_received.empty?
        return @early_received.slice!(0, max_bytes).to_s unless @early_received.empty?
        @machine.read_epoch == :early_data ? "".b : nil
      end

      # A KeyUpdate of our own, and of the peer's too with
      # `request_peer_update: true` (Machine#request_key_update). Raises
      # UsageError before the handshake completes and once the connection
      # failed.
      def request_key_update(request_peer_update: false)
        raise UsageError, "the connection failed" if @failed
        raise UsageError, "our side is closed" if @write_closed
        @machine.request_key_update(request_peer_update:)
        drain_machine
        nil
      end

      # Closes our side (RFC 9846 "Closure Alerts"): a close_notify under the
      # epoch the peer reads, and nothing more after it, not even an alert.
      # The peer's side stays open. Data held for a handshake that has not
      # completed is dropped.
      def close_notify
        raise UsageError, "the connection failed" if @failed
        return nil if @write_closed
        send_alert(@machine.write_epoch, :warning, :close_notify)
        @write_closed = true
        @unsent.clear
        nil
      end

      def handshake_complete? = @machine.complete?

      def failed? = @failed

      # The Machine's events, and Event::PeerAlert, in the order they came.
      def next_event = @events.shift

      private def take(record, now)
        case record.content_type
        when :handshake
          @handshake_received = true
          @machine.receive(record.payload, epoch: @machine.read_epoch, now:)
          limit_record_sizes
          drain_machine
          send_application_data
        when :change_cipher_spec
          # RFC 9846 "Record Protocol": dropped once the first ClientHello
          # is out or in; the record layer has refused it after the peer's
          # Finished.
          return fail!(:unexpected_message, :unexpected_change_cipher_spec) if !@handshake_received && @config.server?
          fail!(:unexpected_message, :interleaved_record) if @machine.partial_message?
        when :alert
          return fail!(:unexpected_message, :interleaved_record) if @machine.partial_message?
          receive_alert(record.payload)
        when :application_data
          return fail!(:unexpected_message, :interleaved_record) if @machine.partial_message?
          return take_early_data(record.payload) if @machine.read_epoch == :early_data
          return fail!(:unexpected_message, :application_data_before_handshake) unless @machine.read_epoch == :application
          @received << record.payload
          # The peer's runs of KeyUpdates and of user_canceled end with data
          # that is not empty.
          unless record.payload.empty?
            @machine.application_data_received
            @consecutive_warning_alerts = 0
          end
        end
      end

      # The client's 0-RTT, as far as the Config takes (RFC 9846 "Early Data
      # Indication").
      private def take_early_data(payload)
        @early_data_size += payload.bytesize
        return fail!(:unexpected_message, :too_much_early_data) if @early_data_size > @config.max_early_data_size
        @early_received << payload
        nil
      end

      # RFC 8449, once the Machine has seen the peer's record_size_limit and
      # before the records it lets out: ours keep to it, and if we sent one
      # too, the peer's keep to ours. A server learns the client's from the
      # ClientHello, before its first flight.
      private def limit_record_sizes
        return if @record_size_limits_set
        peer = @machine.peer_record_size_limit or return
        @record.limit_sizes(send: peer, receive: @config.record_size_limit || Record::DEFAULT_SIZE_LIMIT)
        @record_size_limits_set = true
      end

      # RFC 9846 "Closure Alerts": close_notify after the handshake closes
      # the peer's side only; ours stays open and sends nothing back, as
      # answering at once is what TLS 1.2 did, inviting truncation. During
      # the handshake it is a failure, unauthenticated as the peer still is.
      # RFC 9846 "Error Alerts": every other alert ends the connection,
      # whatever its level, and none is sent back, but for user_canceled,
      # after which we read on until the close_notify that should follow.
      private def receive_alert(payload)
        return fail!(:decode_error, :malformed_alert) unless payload.bytesize == 2
        level, description = payload.unpack("C2").map(&:to_i)
        if IANA.alert_name(description) == :close_notify # steep:ignore
          return close_read if @machine.complete?
          @machine.discard
          @events << ::Raiha::TLS::Event::Failed.new(alert: nil, reason: :peer_closed_during_handshake)
          return stop
        end
        if IANA.alert_name(description) == :user_canceled # steep:ignore
          @consecutive_warning_alerts += 1
          return fail!(:unexpected_message, :too_many_warning_alerts) if @consecutive_warning_alerts > MAX_CONSECUTIVE_WARNING_ALERTS
          @events << Event::PeerAlert.new(level:, description:) # steep:ignore
          return nil
        end
        @events << Event::PeerAlert.new(level:, description:) # steep:ignore
        @machine.discard
        stop
      end

      private def close_read
        @read_closed = true
        nil
      end

      # The Machine's outputs in queue order: each Secret into the key
      # table, each run of Messages of one epoch into as few records as fit,
      # and an alert, after which nothing more is sent.
      private def drain_machine
        runs = @machine.outputs.chunk_while do |a, b|
          a.is_a?(Output::Message) && b.is_a?(Output::Message) && a.epoch == b.epoch
        end
        runs.each do |run|
          case (output = run.first)
          when Output::Message then send_record(:handshake, run.filter_map { |message| message.bytes if message.is_a?(Output::Message) }.join, output.epoch)
          when Output::Secret
            @record.install(direction: output.direction, epoch: output.epoch, secret: output.secret, cipher_suite: output.cipher_suite)
          when Output::Alert then send_alert(output.epoch, output.level, output.description)
          end
        end
        while (event = @machine.next_event)
          make_room_for_a_ticket if event.is_a?(::Raiha::TLS::Event::NewSessionTicket)
          @events << event
        end
        stop if @machine.failed?
      end

      private def make_room_for_a_ticket
        held = @events.count { |event| event.is_a?(::Raiha::TLS::Event::NewSessionTicket) }
        return if held < MAX_HELD_TICKETS
        oldest = @events.index { |event| event.is_a?(::Raiha::TLS::Event::NewSessionTicket) } or return
        @events.delete_at(oldest)
        @tracer&.tls_trace(Trace::TicketIgnored.new(reason: :too_many_tickets))
      end

      private def send_alert(epoch, level, description)
        send_record(:alert, [ALERT_LEVELS.fetch(level), IANA.alert_code(description)].pack("C2"), epoch)
      end

      # Middlebox compatibility (RFC 9846 "Middlebox Compatibility Mode"): a
      # client sends one ChangeCipherSpec before its first protected record,
      # a server right after its first handshake record.
      private def send_record(content_type, payload, epoch)
        return if @write_closed
        change_cipher_spec if @config.client? && epoch != :initial
        @outgoing << @record.write(content_type:, payload:, epoch:)
        change_cipher_spec if @config.server? && content_type == :handshake
      end

      private def change_cipher_spec
        return if @change_cipher_spec_sent
        @change_cipher_spec_sent = true
        @outgoing << @record.write(content_type: :change_cipher_spec, payload: "\x01".b, epoch: :initial)
      end

      # A KeyUpdate the peer asked for first (RFC 9846 "Key and
      # Initialization Vector Update"), then one record at a time, so the key
      # can change between two.
      private def send_application_data
        return if @unsent.empty? || !@machine.complete? || @failed
        @machine.before_application_data
        drain_machine
        until @unsent.empty?
          update_keys_at_the_limit
          chunk = @unsent.byteslice(0, @record.fragment_size(:application)).to_s
          @unsent = @unsent.byteslice(chunk.bytesize..).to_s
          @outgoing << @record.write(content_type: :application_data, payload: chunk, epoch: :application)
        end
      end

      # RFC 9846 "Limits on Key Usage": the key changes before it reaches its
      # suite's limit, by a KeyUpdate under the old key.
      private def update_keys_at_the_limit
        return unless @record.key_update_due?(:application)
        @machine.request_key_update(request_peer_update: false)
        drain_machine
      end

      # A failure found here rather than in the Machine: the alert, under the
      # epoch the peer reads, and Event::Failed.
      private def fail!(alert, reason)
        send_alert(@machine.write_epoch, :fatal, alert)
        @machine.discard
        @events << ::Raiha::TLS::Event::Failed.new(alert:, reason:)
        stop
      end

      # Nothing more is sent or taken, and the keys are forgotten.
      private def stop
        @failed = true
        @record.discard!
        @unsent.clear
        nil
      end
    end
  end
end
