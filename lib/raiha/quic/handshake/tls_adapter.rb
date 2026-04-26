# frozen_string_literal: true

require_relative "../../tls/client"
require_relative "../../tls/server"
require_relative "../../tls/handshake"
require_relative "../../tls/record"
require_relative "../../crypto_util"
require_relative "crypto_setup"

module Raiha::Quic
  module Handshake
    # Bridges QUIC CRYPTO frames with the existing TLS 1.3 implementation.
    #
    # QUIC carries raw TLS handshake messages (without TLS record layer)
    # in CRYPTO frames. This adapter:
    # - Extracts raw handshake bytes from the TLS transcript hash (server)
    # - Feeds raw handshake bytes directly to TLS handler methods (client)
    # - Derives QUIC encryption keys at each handshake stage
    class TLSAdapter
      attr_reader :tls

      def initialize(perspective:, crypto_setup:, tls_config: nil, server_name: nil, transport_parameters: nil, alpn_protocols: nil)
        @perspective = Protocol::Perspective.coerce(perspective)
        @crypto_setup = crypto_setup
        @transport_parameters = transport_parameters

        if @perspective.client?
          @tls = Raiha::TLS::Client.new(config: tls_config, server_name: server_name)
        else
          @tls = Raiha::TLS::Server.new(config: tls_config || Raiha::TLS::Config.server_default)
        end

        inject_transport_parameters_extension
        inject_alpn_extension(alpn_protocols) if alpn_protocols

        @server_hello_sent = false
        @server_flight_sent = false
        @client_finished_sent = false
      end

      # Start the handshake (client sends ClientHello)
      def start
        return unless @perspective.client?

        # Build ClientHello via TLS, extract raw handshake bytes from record
        records = @tls.datagrams_to_send
        records&.each do |record|
          fragment = extract_handshake_fragment(record)
          @crypto_setup.queue_crypto_data(fragment, level: EncryptionLevel::INITIAL) if fragment
        end

        # RFC 9001 §4.1 / §5.1: once the TLS Client has accepted a PSK and
        # derived client_early_traffic_secret, feed the raw secret plus
        # the negotiated cipher suite into CryptoSetup so 0-RTT packets
        # can be encrypted with QUIC keys (key/iv/hp) expanded from it.
        install_early_keys_if_available
      end

      private def install_early_keys_if_available
        tls = @tls
        return unless tls.respond_to?(:early_data_available) && tls.early_data_available
        return unless tls.respond_to?(:client_hello)

        client_hello = tls.client_hello
        return unless client_hello

        secret = tls.key_schedule.client_early_traffic_secret
        return unless secret

        # RFC 9001 §4.1.4: server uses the same cipher_suite it negotiated
        # (available via TLS::Server's negotiated_cipher_suite) while the
        # client uses the one it proposed (only ever one in the
        # ClientHello at this point).
        cipher_suite = if tls.respond_to?(:negotiated_cipher_suite) && tls.negotiated_cipher_suite
                         tls.negotiated_cipher_suite
                       else
                         client_hello.cipher_suites.first
                       end

        @crypto_setup.set_early_keys(
          client_early_traffic_secret: secret,
          cipher_suite: cipher_suite
        )
      end

      # Receive raw TLS handshake data from a CRYPTO frame
      def receive_crypto_data(data, level:)
        if @perspective.server?
          receive_as_server(data, level)
        else
          receive_as_client(data, level)
        end
      end

      def handshake_complete?
        @crypto_setup.handshake_complete?
      end

      # Extract the peer's quic_transport_parameters TLS extension (RFC 9001 Section 8.2)
      # and deserialize into a TransportParameters object, or nil if not yet received.
      def peer_transport_parameters
        return @peer_transport_parameters if defined?(@peer_transport_parameters) && @peer_transport_parameters

        extensions =
          if @perspective.client?
            @tls.encrypted_extensions&.extensions
          else
            @tls.client_hello&.extensions
          end
        return nil unless extensions

        ext = extensions.find { |e| e.is_a?(Raiha::TLS::Handshake::Extension::QuicTransportParameters) }
        return nil unless ext

        @peer_transport_parameters = TransportParameters.deserialize(ext.extension_data)
      end

      # RFC 9001 §4.6.1: when resuming with a ticket that carried QUIC
      # transport parameters, the client uses these remembered values to
      # bound 0-RTT data sent before the server's current parameters
      # arrive in EncryptedExtensions. Returns nil when not resuming, or
      # when the ticket has no associated TP blob.
      def remembered_transport_parameters
        return nil unless @perspective.client?

        store = @tls.instance_variable_get(:@session_ticket_store)
        return nil unless store

        server_name = @tls.instance_variable_get(:@server_name) || ""
        entry = store.get(server_name)
        blob = entry && entry[:application_data]
        return nil unless blob

        TransportParameters.deserialize(blob)
      end

      # Issue a NewSessionTicket on the server side. The current local
      # transport parameters are persisted alongside the ticket so a
      # future resumption can be validated against them (RFC 9001 §4.6.1).
      # Returns raw handshake bytes suitable for transmission in a CRYPTO
      # frame at 1-RTT level, or nil when not applicable.
      def build_new_session_ticket
        return nil unless @perspective.server?
        return nil unless @transport_parameters

        tls = @tls
        return nil unless tls.is_a?(Raiha::TLS::Server)

        application_data = @transport_parameters.serialize
        handshake = tls.build_new_session_ticket_handshake(application_data: application_data)
        handshake.serialize
      end

      private def receive_as_server(data, level)
        case level
        when EncryptionLevel::INITIAL
          # ClientHello: wrap in record for existing TLS Server
          wrapped = wrap_in_plaintext_record(data)
          @tls.receive(wrapped)

          # Update transport parameters extension with latest values (e.g., original_destination_connection_id)
          update_transport_parameters_extension

          # RFC 9001 §4.1.4: if the TLS server accepted the client's
          # early_data extension during select_parameters, bridge the
          # derived client_early_traffic_secret into CryptoSetup so
          # 0-RTT packets from the client can be decrypted.
          install_early_keys_if_available

          # Trigger server to build response flight
          @tls.datagrams_to_send

          # Extract keys
          check_key_derivation

          # Extract raw handshake bytes from transcript hash
          collect_server_response

        when EncryptionLevel::HANDSHAKE
          # Client Finished: feed directly to TLS handler
          handshakes = Raiha::TLS::Handshake.deserialize_multiple(data)
          handshakes.each do |handshake|
            case handshake.message
            when Raiha::TLS::Handshake::Finished
              verify_client_finished(handshake)
            end
          end
        end
      end

      private def verify_client_finished(handshake)
        return unless @tls.verify_client_finished(handshake)

        key_schedule = @tls.key_schedule
        server_hello = @tls.server_hello
        # Handshake complete on server side; install 1-RTT AEAD secrets.
        unless @crypto_setup.available?(EncryptionLevel::ONE_RTT)
          @crypto_setup.set_application_keys(
            client_secret: key_schedule.client_application_traffic_secret.last,
            server_secret: key_schedule.server_application_traffic_secret.last,
            cipher_suite: server_hello.cipher_suite
          )
        end
      end

      private def receive_as_client(data, level)
        # Parse raw handshake messages and feed directly to TLS Client
        handshakes = Raiha::TLS::Handshake.deserialize_multiple(data)
        handshakes.each do |handshake|
          @tls.handle_handshake_message(handshake)
          attach_transport_parameters_to_ticket if handshake.message.is_a?(Raiha::TLS::Handshake::NewSessionTicket)
        end

        check_key_derivation

        # After receiving server Finished, build client Finished
        collect_client_finished
      end

      # Persist the peer's QUIC transport parameters alongside the freshly
      # stored ticket entry (RFC 9001 §4.6.1). Called from the client
      # receive path right after the TLS layer stored a NewSessionTicket.
      private def attach_transport_parameters_to_ticket
        store = @tls.instance_variable_get(:@session_ticket_store)
        return unless store

        server_name = @tls.instance_variable_get(:@server_name) || ""

        peer_tp = peer_transport_parameters
        return unless peer_tp

        store.attach_application_data(server_name, peer_tp.serialize)
      end

      private def collect_server_response
        if !@server_hello_sent && (bytes = @tls.response_flight_bytes(:initial))
          @crypto_setup.queue_crypto_data(bytes, level: EncryptionLevel::INITIAL)
          @server_hello_sent = true
        end

        if !@server_flight_sent && @crypto_setup.available?(EncryptionLevel::HANDSHAKE) &&
            (bytes = @tls.response_flight_bytes(:handshake))
          @crypto_setup.queue_crypto_data(bytes, level: EncryptionLevel::HANDSHAKE)
          @server_flight_sent = true
        end
      end

      private def collect_client_finished
        return if @client_finished_sent
        # Client Finished is transmitted at the Handshake level; emit it only
        # after the server's Finished has been processed (1-RTT keys ready).
        return unless @crypto_setup.available?(EncryptionLevel::ONE_RTT)

        handshake = @tls.build_client_finished_handshake
        return unless handshake

        @crypto_setup.queue_crypto_data(handshake.serialize, level: EncryptionLevel::HANDSHAKE)
        @client_finished_sent = true
      end

      private def extract_handshake_fragment(record)
        return nil unless record.bytesize >= 5

        content_type = record.getbyte(0)
        return nil unless content_type == 22 # Handshake

        fragment_length = record[3..4].unpack1("n")
        record[5, fragment_length]
      end

      private def wrap_in_plaintext_record(handshake_data)
        buf = String.new(encoding: "BINARY")
        buf << [22].pack("C")     # ContentType: Handshake
        buf << "\x03\x03"         # Legacy version: TLS 1.2
        buf << [handshake_data.bytesize].pack("n")
        buf << handshake_data
        buf
      end

      private def update_transport_parameters_extension
        return unless @transport_parameters

        ext = @tls.additional_extensions.find { |e|
          e.is_a?(Raiha::TLS::Handshake::Extension::QuicTransportParameters)
        }
        return unless ext

        ext.transport_parameters_data = @transport_parameters.serialize
      end

      private def inject_alpn_extension(protocols)
        ext = Raiha::TLS::Handshake::Extension::ApplicationLayerProtocolNegotiation.new(
          on: @perspective.client? ? :client_hello : :encrypted_extensions
        )
        ext.protocol_names = protocols
        @tls.additional_extensions << ext
      end

      private def inject_transport_parameters_extension
        return unless @transport_parameters

        ext = Raiha::TLS::Handshake::Extension::QuicTransportParameters.new(
          on: @perspective.client? ? :client_hello : :encrypted_extensions
        )
        ext.transport_parameters_data = @transport_parameters.serialize

        @tls.additional_extensions << ext
      end

      private def check_key_derivation
        key_schedule = @tls.key_schedule
        server_hello = @tls.server_hello

        return unless key_schedule && server_hello

        cipher_suite = server_hello.cipher_suite

        if key_schedule.server_handshake_traffic_secret &&
           !@crypto_setup.available?(EncryptionLevel::HANDSHAKE)
          @crypto_setup.set_handshake_keys(
            client_secret: key_schedule.client_handshake_traffic_secret,
            server_secret: key_schedule.server_handshake_traffic_secret,
            cipher_suite: cipher_suite
          )
        end

        if key_schedule.client_application_traffic_secret&.any? &&
           !@crypto_setup.available?(EncryptionLevel::ONE_RTT)
          @crypto_setup.set_application_keys(
            client_secret: key_schedule.client_application_traffic_secret.last,
            server_secret: key_schedule.server_application_traffic_secret.last,
            cipher_suite: cipher_suite
          )
        end
      end
    end
  end
end
