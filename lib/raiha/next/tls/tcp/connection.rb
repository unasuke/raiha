# frozen_string_literal: true

require_relative "../error"
require_relative "../event"
require_relative "../iana"
require_relative "../output"
require_relative "../record"
require_relative "../handshake/machine"
require_relative "event"

module Raiha::Next::TLS
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

      def self.client(config:, keyring:, server_name:, now:, extensions: [], tracer: nil, keylog: nil)
        new(Handshake::Machine.client(config:, keyring:, server_name:, now:, extensions:, tracer:, keylog:), config)
      end

      def self.server(config:, keyring:, now:, extensions: [], tracer: nil, keylog: nil)
        new(Handshake::Machine.server(config:, keyring:, now:, extensions:, tracer:, keylog:), config)
      end

      private_class_method :new

      def initialize(machine, config)
        @machine = machine
        @config = config
        @record = Record::Layer.new(profile: config.profile)
        @outgoing = "".b
        @unsent = "".b
        @received = "".b
        # @type var events: Array[event]
        events = []
        @events = events
        @failed = false
        @handshake_received = false
        @record_size_limits_set = false
        @change_cipher_spec_sent = !config.profile.compatibility_mode
        drain_machine
      end

      # Bytes read from the socket, in any pieces.
      def receive(bytes, now:)
        return nil if @failed
        @record << bytes
        until @failed || (record = @record.read(epoch: @machine.read_epoch)).nil?
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
        room = WRITE_BUFFER_LIMIT - @unsent.bytesize - @outgoing.bytesize
        taken = data.byteslice(0, room.clamp(0..)).to_s
        @unsent << taken
        send_application_data
        taken.bytesize
      end

      # Up to `max_bytes` of the peer's application data, "" when none has
      # come.
      def read(max_bytes)
        raise UsageError, "the connection failed" if @failed && @received.empty?
        @received.slice!(0, max_bytes).to_s
      end

      # A KeyUpdate of our own, and of the peer's too with
      # `request_peer_update: true` (Machine#request_key_update). Raises
      # UsageError before the handshake completes and once the connection
      # failed.
      def request_key_update(request_peer_update: false)
        raise UsageError, "the connection failed" if @failed
        @machine.request_key_update(request_peer_update:)
        drain_machine
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
          return fail!(:unexpected_message, :application_data_before_handshake) unless @machine.read_epoch == :application
          @received << record.payload
          # The peer's run of KeyUpdates ends with data that is not empty.
          @machine.application_data_received unless record.payload.empty?
        end
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

      # RFC 9846 "Error Alerts": every alert ends the connection, whatever
      # its level, and none is sent back.
      private def receive_alert(payload)
        return fail!(:decode_error, :malformed_alert) unless payload.bytesize == 2
        level, description = payload.unpack("C2").map(&:to_i)
        @events << Event::PeerAlert.new(level:, description:)
        @machine.discard
        stop
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
          @events << event
        end
        stop if @machine.failed?
      end

      private def send_alert(epoch, level, description)
        send_record(:alert, [ALERT_LEVELS.fetch(level), IANA.alert_code(description)].pack("C2"), epoch)
      end

      # Middlebox compatibility (RFC 9846 "Middlebox Compatibility Mode"): a
      # client sends one ChangeCipherSpec before its first protected record,
      # a server right after its first handshake record.
      private def send_record(content_type, payload, epoch)
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
        @events << ::Raiha::Next::TLS::Event::Failed.new(alert:, reason:)
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
