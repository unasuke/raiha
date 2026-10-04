# frozen_string_literal: true

require_relative "../error"
require_relative "../extension"
require_relative "../output"
require_relative "../server_name"
require_relative "client_hello"
require_relative "reassembler"

module Raiha::Next::TLS
  module Handshake
    # A ClientHello and what the application may choose a Config by. All of
    # it is unauthenticated, and with 0-RTT it may be replayed. PSK
    # identities, key shares and binders are left out on purpose.
    #
    # Values from the peer stay Integers. `server_name` is in normal form,
    # or nil when there was none or it was not a usable host name.
    # `after_hello_retry_request` says the ClientHello carries a cookie.
    class ClientHelloInfo < Data.define(
      :server_name, :alpn_protocols, :cipher_suites, :supported_groups,
      :signature_algorithms, :extension_types, :psk_offered, :early_data_offered, :after_hello_retry_request
    )
    end

    # The ClientHello, as the bytes that came over the wire, with its info.
    # A value, not a token: making two Machines of one is the caller's bug.
    class Accepted < Data.define(:bytes, :info)
    end

    # The start of a server's handshake, before a Config is chosen: it takes
    # :initial bytes until a ClientHello is whole, checks it on its own
    # (parsing, placement and the checks that need no context) and offers
    # it as an Accepted. The application picks a Config and a Keyring by it,
    # by SNI say, and starts a Machine with it; or turns it down with
    # `reject`. It needs neither Config nor Profile.
    #
    # Bytes from the peer never raise. The only output is an Output::Alert.
    class Acceptor
      MAX_CLIENT_HELLO_SIZE = 16 * 1024

      # Reasons to turn a ClientHello down before anything in it is
      # authenticated. The alerts that report broken messages are the
      # Acceptor's own, and access_denied needs an authenticated peer.
      REJECT_ALERTS = %i[
        unrecognized_name missing_extension no_application_protocol handshake_failure
        insufficient_security internal_error general_error
      ].freeze

      EXPECTED = Set[ClientHello::MSG_TYPE].freeze
      NOTHING = Set.new.freeze #: Set[Integer]

      attr_reader :alert, :reason

      def initialize
        @reassembler = Reassembler.new(limits: ->(_) { MAX_CLIENT_HELLO_SIZE })
        @reassembler.expect(EXPECTED)
        @accepted = nil #: Accepted?
        @alert = nil #: Symbol?
        @reason = nil #: Symbol?
        # @type var outputs: Array[Output::Alert]
        outputs = []
        @outputs = outputs
      end

      def failed? = !@alert.nil?

      # The ClientHello once whole and valid; nil before, and after a failure.
      def accepted = failed? ? nil : @accepted

      # A server reads only :initial bytes before it has keys, so any other
      # epoch is the caller's mistake.
      def receive(bytes, epoch:, now:)
        raise UsageError, "an Acceptor takes only :initial bytes, not #{epoch.inspect}" unless epoch == :initial
        return nil if failed?
        return fail!(:unexpected_message, :data_after_client_hello) if @accepted
        status = @reassembler << bytes
        status = @reassembler.each_message { |_, body| break accept(body) } if status == :ok
        case status
        when :overflow then fail!(:decode_error, :message_too_large)
        when :unexpected then fail!(:unexpected_message, :unexpected_message)
        end
        fail!(:unexpected_message, :data_after_client_hello) if @accepted && @reassembler.pending?
        nil
      end

      def each_output
        while (output = @outputs.shift)
          yield output
        end
      end

      # Turns the ClientHello down with one of REJECT_ALERTS.
      def reject(description)
        raise ArgumentError, "reject takes one of #{REJECT_ALERTS.inspect}, not #{description.inspect}" unless REJECT_ALERTS.include?(description)
        fail!(description, :rejected)
      end

      private def accept(body)
        @reassembler.expect(NOTHING)
        raw = [ClientHello::MSG_TYPE, body.bytesize >> 16, body.bytesize >> 8 & 0xff, body.bytesize & 0xff].pack("C4") + body
        begin
          client_hello = ClientHello.parse_body(body, registry: Extension::Registry::BUILTIN)
        rescue Codec::Malformed => e
          return fail!(e.alert, :malformed_message)
        end
        if (violation = client_hello.validate)
          return fail!(violation.alert, violation.reason)
        end
        @accepted = Accepted.new(bytes: raw.freeze, info: info(client_hello))
        :ok
      end

      private def info(ch)
        name = case (ext = ch.extension(Extension::ServerName::TYPE))
          when Extension::ServerName::CH then ext.host_name&.then { |host_name| ServerName.for_server(host_name).first }
          end
        # @type var alpn: Array[String]
        alpn = case (ext = ch.extension(Extension::Alpn::TYPE))
          when Extension::Alpn then ext.protocol_name_list
          else []
          end
        # @type var groups: Array[Integer]
        groups = case (ext = ch.extension(Extension::SupportedGroups::TYPE))
          when Extension::SupportedGroups then ext.named_group_list
          else []
          end
        # @type var algorithms: Array[Integer]
        algorithms = case (ext = ch.extension(Extension::SignatureAlgorithms::TYPE))
          when Extension::SignatureAlgorithms then ext.supported_signature_algorithms
          else []
          end
        types = ch.extensions.map(&:extension_type)
        ClientHelloInfo.new(
          server_name: name, alpn_protocols: alpn, cipher_suites: ch.cipher_suites, supported_groups: groups,
          signature_algorithms: algorithms, extension_types: types,
          psk_offered: types.include?(Extension::PreSharedKey::TYPE),
          early_data_offered: types.include?(Extension::EarlyData::TYPE),
          after_hello_retry_request: types.include?(Extension::Cookie::TYPE)
        )
      end

      # The Acceptor's one place to build an alert, before any Machine
      # exists to own it.
      private def fail!(alert, reason)
        return nil if failed?
        @alert = alert
        @reason = reason
        @outputs << Output::Alert.new(level: :fatal, description: alert, epoch: :initial)
        nil
      end
    end
  end
end
