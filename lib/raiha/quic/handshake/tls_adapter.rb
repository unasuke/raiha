# frozen_string_literal: true

require_relative "../../tls/client"
require_relative "../../tls/server"
require_relative "../../tls/handshake"
require_relative "../../tls/record"
require_relative "crypto_setup"

module Raiha::Quic
  module Handshake
    # Bridges QUIC CRYPTO frames with the existing TLS 1.3 implementation.
    # QUIC carries raw TLS handshake messages (without TLS record layer)
    # in CRYPTO frames. This adapter wraps/unwraps the record layer
    # for compatibility with the existing TLS Client/Server.
    class TLSAdapter
      attr_reader :tls

      def initialize(perspective:, crypto_setup:, tls_config: nil, server_name: nil)
        @perspective = perspective
        @crypto_setup = crypto_setup

        if perspective == Protocol::Perspective::CLIENT
          @tls = Raiha::TLS::Client.new(config: tls_config, server_name: server_name)
        else
          @tls = Raiha::TLS::Server.new(config: tls_config || Raiha::TLS::Config.server_default)
        end

        @handshake_bytes_to_send = String.new(encoding: "BINARY")
      end

      # Start the handshake (client sends ClientHello)
      def start
        return unless @perspective == Protocol::Perspective::CLIENT

        # Build ClientHello and extract raw handshake bytes
        records = @tls.datagrams_to_send
        records&.each do |record|
          extract_handshake_from_record(record)
        end

        flush_to_crypto_setup(EncryptionLevel::INITIAL)
      end

      # Receive raw TLS handshake data from a CRYPTO frame
      def receive_crypto_data(data, level:)
        # Wrap raw handshake bytes in a TLS record for the existing TLS implementation
        wrapped = wrap_in_record(data)
        @tls.receive(wrapped)

        # Check for handshake progress and derive keys
        check_key_derivation

        # Collect any response handshake data
        collect_response_data(level)

        # Re-check after collecting response (server derives keys during datagrams_to_send)
        check_key_derivation
      end

      # Check if the TLS handshake is complete
      def handshake_complete?
        @tls.finished? rescue false
      end

      private def extract_handshake_from_record(record)
        # TLS record format: content_type(1) + version(2) + length(2) + fragment
        # We want just the fragment (handshake message bytes)
        if record.bytesize >= 5
          content_type = record.getbyte(0)
          fragment_length = record[3..4].unpack1("n")
          fragment = record[5, fragment_length]
          @handshake_bytes_to_send << fragment if content_type == 22 # Handshake
        end
      end

      private def wrap_in_record(handshake_data)
        # Wrap raw handshake bytes in a TLS plaintext record
        buf = String.new(encoding: "BINARY")
        buf << [22].pack("C")      # ContentType: Handshake
        buf << "\x03\x03"          # Legacy version: TLS 1.2
        buf << [handshake_data.bytesize].pack("n")
        buf << handshake_data
        buf
      end

      private def flush_to_crypto_setup(level)
        unless @handshake_bytes_to_send.empty?
          @crypto_setup.queue_crypto_data(@handshake_bytes_to_send, level: level)
          @handshake_bytes_to_send = String.new(encoding: "BINARY")
        end
      end

      private def check_key_derivation
        key_schedule = @tls.instance_variable_get(:@key_schedule)
        server_hello = @tls.instance_variable_get(:@server_hello)

        return unless key_schedule && server_hello

        cipher_suite = server_hello.cipher_suite

        # Check for handshake keys
        if key_schedule.server_handshake_traffic_secret &&
           !@crypto_setup.available?(EncryptionLevel::HANDSHAKE)
          @crypto_setup.set_handshake_keys(
            client_secret: key_schedule.client_handshake_traffic_secret,
            server_secret: key_schedule.server_handshake_traffic_secret,
            cipher_suite: cipher_suite
          )
        end

        # Check for application keys
        if key_schedule.client_application_traffic_secret&.any? &&
           !@crypto_setup.available?(EncryptionLevel::ONE_RTT)
          @crypto_setup.set_application_keys(
            client_secret: key_schedule.client_application_traffic_secret.last,
            server_secret: key_schedule.server_application_traffic_secret.last,
            cipher_suite: cipher_suite
          )
        end
      end

      private def collect_response_data(current_level)
        # For server: after receiving ClientHello, collect all response messages
        if @perspective == Protocol::Perspective::SERVER
          records = @tls.datagrams_to_send
          records&.flatten&.each do |record|
            next unless record.is_a?(String)

            extract_handshake_from_record(record)
          end

          # Server's initial response goes in Handshake level (after ServerHello)
          response_level = @crypto_setup.available?(EncryptionLevel::HANDSHAKE) ? EncryptionLevel::HANDSHAKE : current_level
          flush_to_crypto_setup(response_level)
        end

        # For client: after receiving server flight, collect Finished
        if @perspective == Protocol::Perspective::CLIENT
          records = @tls.datagrams_to_send
          records&.each do |record|
            next unless record.is_a?(String)

            extract_handshake_from_record(record)
          end

          response_level = @crypto_setup.available?(EncryptionLevel::HANDSHAKE) ? EncryptionLevel::HANDSHAKE : current_level
          flush_to_crypto_setup(response_level)
        end
      end
    end
  end
end
