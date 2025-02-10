# frozen_string_literal: true

require_relative "context"
require_relative "record"
require_relative "handshake"
require_relative "key_schedule"
require_relative "aead"
require_relative "../crypto_util"

module Raiha
  module TLS
    class Client < Context
      module State
        START = :START
        WAIT_SH = :WAIT_SH
        WAIT_EE = :WAIT_EE
        WAIT_CERT_CR = :WAIT_CERT_CR
        WAIT_CERT = :WAIT_CERT
        WAIT_CV = :WAIT_CV
        WAIT_FINISHED = :WAIT_FINISHED
        CONNECTED = :CONNECTED
      end

      attr_reader :state

      def initialize
        super
        @state = State::START
        @buffer = []
        @supported_groups = []
        @transcript_hash = {}
        @client_hello = nil
        @server_hello = nil
        @received = []
        @key_schedule = KeySchedule.new(mode: :client)
        @groups = ["prime256v1"]
        @pkeys = @groups.map { |group| { group: group, pkey: OpenSSL::PKey::EC.generate(group) } }
        @server_cipher = nil
        @client_cipher = nil
      end

      def datagrams_to_send
        case @state
        when State::START
          build_client_hello.tap do
            transition_state(State::WAIT_SH)
          end
        when State::CONNECTED
          @buffer
        end
      ensure
        @buffer = []
      end

      def receive(datagram)
        @received = Record.deserialize(datagram)
        loop do
          case @state
          when State::WAIT_SH
            receive_server_hello
          when State::WAIT_EE
            receive_encrypted_extensions
          when State::WAIT_CERT_CR
            receive_certificate_or_certificate_request
          when State::WAIT_CV
            receive_certificate_verify
          when State::WAIT_FINISHED
            receive_finished
          else
            # TODO: WIP
          end
          break if @received.empty?
        end
      end


      def receive_server_hello
        @received.each.with_index do |record, idx|
          # TODO: check change_cipher_spec
          case
          when record.is_a?(Record::TLSPlaintext) && record.fragment.is_a?(Handshake) && record.fragment.message.is_a?(Handshake::ServerHello)
            # TODO: HelloRetryRequest
            @server_hello = record.fragment.message
            if valid_server_hello?
              @transcript_hash[:server_hello] = record.fragment
              setup_key_schedule
              setup_cipher
              transition_state(State::WAIT_EE)
            end
            @received.delete_at(idx)
            break
          end
        end
      end

      # Accepts EncryptedExtensions message, if find ChangeCipherSpec message, ignore it
      def receive_encrypted_extensions
        loop do
          received = @received.shift
          break if received.nil?

          # verify timing
          if received.is_a?(Record::TLSPlaintext) &&
            received.fragment.is_a?(Handshake) &&
            received.fragment.message.is_a?(Handshake::ChangeCipherSpec)
            next
          end

          next unless received.is_a?(Record::TLSCiphertext)

          inner_plaintext = @server_cipher.decrypt(ciphertext: received, phase: :handshake)
          next unless inner_plaintext.is_a?(Record::TLSInnerPlaintext)

          handshakes = Handshake.deserialize_multiple(inner_plaintext.content)
          encrypted_extensions = handshakes.find { |hs| hs.message.is_a?(Handshake::EncryptedExtensions) }

          if encrypted_extensions
            @transcript_hash[:encrypted_extensions] = encrypted_extensions
            transition_state(State::WAIT_CERT_CR)
            break
          end
        end
      end

      # Accepts CertificateRequest message or Certificate message
      def receive_certificate_or_certificate_request
        loop do
          received = @received.shift
          break if received.nil?
          next unless received.is_a?(Record::TLSCiphertext)

          inner_plaintext = @server_cipher.decrypt(ciphertext: received, phase: :handshake)
          next unless inner_plaintext.is_a?(Record::TLSInnerPlaintext)

          handshakes = Handshake.deserialize_multiple(inner_plaintext.content)
          # certificate_request = handshakes.find { |hs| hs.message.is_a?(Handshake::CertificateRequest) }
          certificate = handshakes.find { |hs| hs.message.is_a?(Handshake::Certificate) }
          if certificate
            @transcript_hash[:certificate] = certificate
            transition_state(State::WAIT_CV)
            break
          end
        end
      end

      # Accepts CertificateVerify message
      def receive_certificate_verify
        loop do
          received = @received.shift
          break if received.nil?
          next unless received.is_a?(Record::TLSCiphertext)

          inner_plaintext = @server_cipher.decrypt(ciphertext: received, phase: :handshake)
          next unless inner_plaintext.is_a?(Record::TLSInnerPlaintext)

          handshakes = Handshake.deserialize_multiple(inner_plaintext.content)
          certificate_verify = handshakes.find { |hs| hs.message.is_a?(Handshake::CertificateVerify) }
          if certificate_verify
            verify_certificate_verify(certificate_verify)
            @transcript_hash[:certificate_verify] = certificate_verify
            transition_state(State::WAIT_FINISHED)
            break
          end
        end
      end

      def receive_finished
        loop do
          received = @received.shift
          break if received.nil?
          next unless received.is_a?(Record::TLSCiphertext)

          inner_plaintext = @server_cipher.decrypt(ciphertext: received, phase: :handshake)
          next unless inner_plaintext.is_a?(Record::TLSInnerPlaintext)

          handshakes = Handshake.deserialize_multiple(inner_plaintext.content)
          finished = handshakes.find { |hs| hs.message.is_a?(Handshake::Finished) }
          if finished
            verify_finished(finished)
            @transcript_hash[:finished] = finished
            derive_application_traffic_secrets
            respond_to_finished
            transition_state(State::CONNECTED)
            break
          end
        end
      end

      def build_client_hello
        hs_clienthello = Raiha::TLS::Handshake.new.tap do |hs|
          hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
          hs.message = Raiha::TLS::Handshake::ClientHello.build
        end
        hs_clienthello.message.setup_key_share(@pkeys)
        @client_hello = hs_clienthello.message
        @transcript_hash[:client_hello] = hs_clienthello
        # hs_clienthello.serialize
        Record::TLSPlaintext.serialize(hs_clienthello)
      end

      def respond_to_finished
        finished = Handshake::Finished.new.tap do |fin|
          fin.verify_data = finished_verify_data(
            [
              @transcript_hash[:client_hello].serialize,
              @transcript_hash[:server_hello].serialize,
              @transcript_hash[:encrypted_extensions].serialize,
              @transcript_hash[:certificate].serialize,
              @transcript_hash[:certificate_verify].serialize,
              @transcript_hash[:finished].serialize,
            ], @key_schedule.client_handshake_traffic_secret
          )
        end
        hs_finished = Raiha::TLS::Handshake.new.tap do |hs|
          hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:finished]
          hs.message = finished
        end
        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = hs_finished.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        ciphertext = @client_cipher.encrypt(plaintext: innerplaintext, phase: :handshake)
        @buffer << ciphertext.serialize
      end

      def finished?
        @state == State::CONNECTED
      end

      private def transition_state(state)
        if @state == State::START && state == State::WAIT_SH
          @state = state
        elsif @state == State::WAIT_SH && state == State::WAIT_EE
          @state = state
        elsif @state == State::WAIT_EE && state == State::WAIT_CERT_CR
          @state = state
        elsif @state == State::WAIT_CERT_CR && state == State::WAIT_CV
          @state = state
        elsif @state == State::WAIT_CV && state == State::WAIT_FINISHED
          @state = state
        elsif @state == State::WAIT_FINISHED && state == State::CONNECTED
          @state = state
        else
          raise "TODO: #{@state} -> #{state} is wrong state transition"
        end
      end

      private def valid_server_hello?
        return false unless @server_hello.legacy_session_id_echo == @client_hello.legacy_session_id
        return false unless @client_hello.cipher_suites.map(&:name).include?(@server_hello.cipher_suite.name)

        @server_hello.extensions.any? { |ext|
          # TODO: validate value by extension itself
          ext.is_a?(Raiha::TLS::Handshake::Extension::SupportedVersions) && ext.extension_data == "\x03\x04"
        }
        @server_hello.extensions.any? { |ext|
          # TODO: validate value by extension itself
          ext.is_a?(Raiha::TLS::Handshake::Extension::KeyShare)
          # TODO: check pre_shared_key or key_share
        }
        # TODO: check returned extensions and send setensions
      end

      private def setup_key_schedule
        server_key_share = @server_hello.key_share
        @key_schedule.cipher_suite = @server_hello.cipher_suite
        @key_schedule.group = server_key_share.groups.first[:group]
        @key_schedule.public_key = server_key_share.groups.first[:key_exchange]
        @key_schedule.pkey = @pkeys.find { |pkeys| pkeys[:group] == server_key_share.groups.first[:group] }[:pkey]
        @key_schedule.compute_shared_secret
        @key_schedule.derive_secret(secret: :early_secret, label: "derived", messages: [""])
        @key_schedule.derive_client_handshake_traffic_secret([@transcript_hash[:client_hello], @transcript_hash[:server_hello]])
        @key_schedule.derive_server_handshake_traffic_secret([@transcript_hash[:client_hello], @transcript_hash[:server_hello]])
      end

      private def setup_cipher
        @server_cipher = AEAD.new(cipher_suite: @server_hello.cipher_suite, key_schedule: @key_schedule, mode: :server)
        @client_cipher = AEAD.new(cipher_suite: @server_hello.cipher_suite, key_schedule: @key_schedule, mode: :client)
      end

      private def verify_certificate_verify(certificate_verify)
        raise unless certificate_verify.message.verify_signature(
          @transcript_hash[:certificate].message,
          [
            @transcript_hash[:client_hello].serialize,
            @transcript_hash[:server_hello].serialize,
            @transcript_hash[:encrypted_extensions].serialize,
            @transcript_hash[:certificate].serialize,
          ],
          "TLS 1.3, server CertificateVerify"
        )
      end

      private def verify_finished(finished)
        # CryptoUtil.hkdf_expand_label("secret", "finished", context, length)
        # finished_key  = @key_schedule.hkdf_expand()
        messages = [
          @transcript_hash[:client_hello].serialize,
          @transcript_hash[:server_hello].serialize,
          @transcript_hash[:encrypted_extensions].serialize,
          @transcript_hash[:certificate].serialize,
          @transcript_hash[:certificate_verify].serialize,
        ]
        raise unless finished.message.verify_data == finished_verify_data(messages, @key_schedule.server_handshake_traffic_secret)
      end

      private def derive_application_traffic_secrets
        messages = [
          @transcript_hash[:client_hello],
          @transcript_hash[:server_hello],
          @transcript_hash[:encrypted_extensions],
          @transcript_hash[:certificate],
          @transcript_hash[:certificate_verify],
          @transcript_hash[:finished],
        ]
        @key_schedule.derive_client_application_traffic_secret(messages)
        @key_schedule.derive_server_application_traffic_secret(messages)
      end

      private def finished_verify_data(messages, key)
        # TODO: don't hardcode hash algorithm
        finished_key = CryptoUtil.hkdf_expand_label(key, "finished", "", OpenSSL::Digest.new("sha256").digest_length)
        OpenSSL::HMAC.digest("sha256", finished_key, @key_schedule.transcript_hash(messages))
      end
    end
  end
end
