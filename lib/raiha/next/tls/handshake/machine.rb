# frozen_string_literal: true

require_relative "../config"
require_relative "../error"
require_relative "../key_schedule"
require_relative "../keyring"
require_relative "../server_name"
require_relative "acceptor"
require_relative "client_side"
require_relative "conductor"
require_relative "server_side"

module Raiha::Next::TLS
  module Handshake
    # A TLS 1.3 handshake without I/O: handshake bytes in, an ordered queue of
    # Outputs (messages, secrets, alerts) and Events out. The transport, TCP
    # records or QUIC CRYPTO frames, carries the bytes and installs the keys.
    #
    # Bytes from the peer never raise: a failure is an Output::Alert and an
    # Event::Failed. Misuse by the caller raises UsageError. An exception from
    # an object the caller gave (the Verifier, the tracer) is not caught: the
    # handshake forgets its secrets, fails and lets it through.
    class Machine
      # Starts a client, which queues its ClientHello at once. `server_name`
      # is a DNS name (A-labels) or an IP address literal; an address is
      # checked against the certificate but not sent as SNI. `extensions` are
      # this connection's own, beside the Config's. `keylog`, anything with
      # `#write(String)`, gets a Keylog line for each traffic secret: never in
      # production (RFC 9850).
      # `session` is one to resume, offered if it still passes the client's
      # checks at `now`, else reported by Event::SessionNotOffered.
      def self.client(config:, keyring:, server_name:, now:, extensions: [], tracer: nil, keylog: nil, session: nil, early_data: false)
        start_client(config:, keyring:, server_name:, now:, extensions:, tracer:, keylog:, substitutions: nil, session:, early_data:)
      end

      # Starts a server on the ClientHello an Acceptor offered; everything up
      # to the first flight happens here. Without one, the Machine takes the
      # ClientHello through `receive` with an Acceptor of its own, for a
      # server that does not choose its Config by the ClientHello.
      # `resumption_binding` is what the layer above binds the tickets of the
      # connection to, a ticket bound to another failing to open (the QUIC
      # version); `early_data_context` is what a ticket keeps for 0-RTT to be
      # taken on it later only if the same. `anti_replay` records the
      # ClientHellos whose 0-RTT was taken (AntiReplay), and a Config that
      # takes 0-RTT needs one.
      def self.server(config:, keyring:, now:, client_hello: nil, extensions: [], tracer: nil, keylog: nil,
        resumption_binding: "".b, early_data_context: "".b, anti_replay: nil)
        start_server(config:, keyring:, client_hello:, now:, extensions:, tracer:, keylog:, substitutions: nil,
          resumption_binding:, early_data_context:, anti_replay:)
      end

      # The constructors, with the `substitutions` only Test::RFC8448 passes.
      private_class_method def self.start_client(config:, keyring:, server_name:, now:, extensions:, tracer:, keylog:, substitutions:,
        session: nil, early_data: false)
        raise ArgumentError, "Machine.client takes a client Config" unless config.client?
        check(config, keyring, extensions)
        raise ArgumentError, "session must be a Session" unless session.nil? || session.is_a?(Session)
        raise UsageError, "a Config with resumption: false resumes no session" if session && !config.resumption
        raise ArgumentError, "early_data must be true or false" unless early_data == true || early_data == false
        sni, name = ServerName.for_client(server_name)
        new(config:, keyring:, tracer:, keylog:, substitutions:, now:, client_hello: nil) do |conductor|
          ClientSide.new(conductor, server_name: name, sni:, extensions:, tracer:, session:, early_data:)
        end
      end

      private_class_method def self.start_server(config:, keyring:, client_hello:, now:, extensions:, tracer:, keylog:, substitutions:,
        resumption_binding: "".b, early_data_context: "".b, anti_replay: nil)
        raise ArgumentError, "Machine.server takes a server Config" unless config.server?
        check(config, keyring, extensions)
        unless resumption_binding.is_a?(String) && early_data_context.is_a?(String)
          raise ArgumentError, "resumption_binding and early_data_context must be Strings"
        end
        # Without a record, 0-RTT the tickets allow could never be taken.
        raise UsageError, "a Config that takes 0-RTT needs anti_replay:" unless anti_replay || config.max_early_data_size.zero?
        new(config:, keyring:, tracer:, keylog:, substitutions:, now:, client_hello: client_hello || Acceptor.new) do |conductor|
          ServerSide.new(conductor, extensions:, tracer:, resumption_binding: resumption_binding.b, early_data_context: early_data_context.b,
            anti_replay:)
        end
      end

      private_class_method def self.check(config, keyring, extensions)
        raise ArgumentError, "the Keyring was built for another Config" unless keyring.config.equal?(config)
        Config.check_extensions(extensions, config.registry)
        overlap = extensions.map(&:extension_type) & config.extensions.map(&:extension_type)
        raise ArgumentError, "extensions #{overlap.inspect} are set in the Config already" unless overlap.empty?
      end

      private_class_method :new

      # A client starts by sending; a server by receiving its ClientHello,
      # given or still to come through its Acceptor.
      def initialize(config:, keyring:, tracer:, keylog:, substitutions:, now:, client_hello:, &side)
        @config = config
        @conductor = Conductor.new(config:, keyring:, tracer:, keylog:, substitutions:, &side)
        @acceptor = nil #: Acceptor?
        case client_hello
        when Accepted then @conductor.receive_message(:initial, client_hello.bytes, now:)
        when Acceptor then @acceptor = client_hello
        else @conductor.start(now:)
        end
      end

      # The peer's handshake bytes of `epoch`, in order; a message may be
      # split anywhere. Ignored once failed.
      def receive(bytes, epoch:, now:)
        if (acceptor = @acceptor)
          acceptor.receive(bytes, epoch:, now:)
          if (failure = acceptor.alert)
            @acceptor = nil
            @conductor.fail!(failure, acceptor.reason || :unexpected_message)
          elsif (accepted = acceptor.accepted)
            @acceptor = nil
            @conductor.receive_message(:initial, accepted.bytes, now:)
          end
        else
          @conductor.receive(bytes, epoch:, now:)
        end
        nil
      end

      def each_output(&)
        return enum_for(:each_output) unless block_given?
        @conductor.each_output(&)
      end

      # Takes every queued output.
      def outputs
        # @type var taken: Array[Output::t]
        taken = []
        @conductor.each_output { |output| taken << output }
        taken
      end

      def next_event = @conductor.next_event

      def each_event
        return enum_for(:each_event) unless block_given?
        while (event = next_event)
          yield event
        end
      end

      # The epoch of the next handshake bytes to pass in.
      def read_epoch = @conductor.read_epoch

      # Part of a handshake message has come, but not all of it. Over TCP no
      # other kind of record may come in between (RFC 9846 "Record Layer").
      def partial_message? = @acceptor&.partial_message? || @conductor.pending_input?

      # The epoch to send an alert under now: the one the peer reads.
      def write_epoch = @conductor.write_epoch

      # Our Finished is sent and the peer's verified.
      def complete? = @conductor.state == :connected

      # A KeyUpdate of our own over TCP: Message(:application, KeyUpdate)
      # under the old key, then the next Secret(:application, :write). A
      # KeyUpdate the peer asked for goes first. Raises UsageError before the
      # handshake is complete and with Profile::QUIC.
      def request_key_update(request_peer_update: false) = @conductor.request_key_update(request_peer_update:)

      # The TCP binding calls this right before it sends application data,
      # which is when a KeyUpdate the peer asked for goes out (RFC 9846 "Key
      # and Initialization Vector Update").
      def before_application_data = @conductor.before_application_data

      # The TCP binding calls this when a record of application data, not
      # empty, arrives: the peer's run of KeyUpdates ends there.
      def application_data_received = @conductor.application_data_received

      # How many KeyUpdates we have sent.
      def key_update_epoch = @conductor.side.key_updates

      # The record_size_limit the peer sent (RFC 8449), the most our
      # protected records to it may carry, content type included; nil
      # without one. A client learns it from EncryptedExtensions, a server
      # from the ClientHello.
      def peer_record_size_limit = @conductor.side.peer_record_size_limit

      # How many bytes of 0-RTT records a server's record layer skips (RFC
      # 9846 "Early Data Indication"): the Config's max_early_data_size, or
      # 16 KiB if more, when the ClientHello offered 0-RTT that was not
      # taken, else nil. Records
      # of application_data while `read_epoch` is :initial (after a
      # HelloRetryRequest), records that do not open under the handshake key
      # while it is :handshake; the record layer counts them and ends the
      # skipping. Nil for a client, and where there is no record layer.
      def skip_early_data_limit = @conductor.side.skip_early_data_limit

      def failed? = @conductor.failed?

      def alert = @conductor.alert

      def cipher_suite = @conductor.side.cipher_suite&.name

      def group = @conductor.side.group

      def alpn = @conductor.side.alpn

      def peer_certificates = @conductor.side.peer_certificates

      # RFC 9846 "Exporters", for a label declared in the Config's
      # `exporter_labels`. A missing context and an empty one are the same.
      def export_keying_material(label:, length:, context: "".b)
        raise UsageError, "the handshake is not complete" unless complete?
        side = @conductor.side
        inner = side.exporter_values[label] or raise UsageError, "#{label.inspect} is not in the Config's exporter_labels"
        suite = side.cipher_suite or raise UsageError, "the handshake is not complete"
        KeySchedule.export(inner_value: inner, context:, length:, hash: suite.hash_algorithm)
      end

      # The most handshake data the peer may send in `epoch`, for a QUIC
      # binding to bound its CRYPTO buffer: the sum of the limits on the
      # messages the peer can send there.
      def max_flight_size(epoch)
        h = @config.max_handshake_message_size
        c = @config.max_certificate_message_size
        case [@config.role, epoch]
        in [:client, :initial] then h
        in [:client, :handshake] then 2 * c + 3 * h
        in [:client, :application] then h
        in [:server, :initial] then h
        in [:server, :handshake] then @config.client_auth == :none ? h : c + 2 * h
        else 0
        end
      end

      # The connection ended outside the handshake: forget every secret and
      # stop, without output or event. Idempotent.
      def discard
        @conductor.discard!
        nil
      end

      def inspect = "#<#{self.class.name} #{@config.role} #{@conductor.state.inspect}>"
    end
  end
end
