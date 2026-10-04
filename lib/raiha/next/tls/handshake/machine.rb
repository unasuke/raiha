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
      # this connection's own, beside the Config's.
      def self.client(config:, keyring:, server_name:, now:, extensions: [], tracer: nil)
        start_client(config:, keyring:, server_name:, now:, extensions:, tracer:, substitutions: nil)
      end

      # Starts a server on the ClientHello an Acceptor offered; everything up
      # to the first flight happens here. Without one, the Machine takes the
      # ClientHello through `receive` with an Acceptor of its own, for a
      # server that does not choose its Config by the ClientHello.
      def self.server(config:, keyring:, now:, client_hello: nil, extensions: [], tracer: nil)
        start_server(config:, keyring:, client_hello:, now:, extensions:, tracer:, substitutions: nil)
      end

      # The constructors, with the `substitutions` only Test::RFC8448 passes.
      private_class_method def self.start_client(config:, keyring:, server_name:, now:, extensions:, tracer:, substitutions:)
        raise ArgumentError, "Machine.client takes a client Config" unless config.client?
        check(config, keyring, extensions)
        sni, name = ServerName.for_client(server_name)
        new(config:, keyring:, tracer:, substitutions:, now:, client_hello: nil) do |conductor|
          ClientSide.new(conductor, server_name: name, sni:, extensions:, tracer:)
        end
      end

      private_class_method def self.start_server(config:, keyring:, client_hello:, now:, extensions:, tracer:, substitutions:)
        raise ArgumentError, "Machine.server takes a server Config" unless config.server?
        check(config, keyring, extensions)
        new(config:, keyring:, tracer:, substitutions:, now:, client_hello: client_hello || Acceptor.new) do |conductor|
          ServerSide.new(conductor, extensions:, tracer:)
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
      def initialize(config:, keyring:, tracer:, substitutions:, now:, client_hello:, &side)
        @config = config
        @conductor = Conductor.new(config:, keyring:, tracer:, substitutions:, &side)
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

      # The epoch to send an alert under now: the one the peer reads.
      def write_epoch = @conductor.write_epoch

      # Our Finished is sent and the peer's verified.
      def complete? = @conductor.state == :connected

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

      # How much a TCP server should read past of rejected 0-RTT data. No
      # 0-RTT is accepted or offered yet, so nil.
      def skip_early_data_limit = nil

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
