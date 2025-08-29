# frozen_string_literal: true

require_relative "alert"
require_relative "application_data"
require_relative "context"
require_relative "config"
require_relative "peer"
require_relative "record"
require_relative "handshake"
require_relative "key_schedule"
require_relative "aead"
require_relative "transcript_hash"
require_relative "../crypto_util"

module Raiha
  module TLS
    class Client < Peer
      module State
        START = :START
        WAIT_SH = :WAIT_SH
        WAIT_EE = :WAIT_EE
        WAIT_CERT_CR = :WAIT_CERT_CR
        WAIT_CERT = :WAIT_CERT
        WAIT_CV = :WAIT_CV
        WAIT_FINISHED = :WAIT_FINISHED
        WAIT_SEND_FINISHED = :WAIT_SEND_FINISHED
        CONNECTED = :CONNECTED
      end

      attr_reader :state

      def initialize(config: nil, server_name: nil)
        super()
        @config = config || Config.client_default
        @state = State::START
        @receive_buffer = ""
        @buffer = []
        @supported_groups = @config.supported_groups
        @transcript_hash = TranscriptHash.new
        @client_hello = nil
        @server_hello = nil
        @received = []
        @key_schedule = KeySchedule.new(mode: :client)
        @groups = @config.supported_groups
        @pkeys = @groups.map { |group| { group: group, pkey: OpenSSL::PKey::EC.generate(group) } }
        @server_cipher = nil
        @client_cipher = nil
        @current_phase = :handshake
        @server_name = server_name
      end

      def datagrams_to_send
        case @state
        when State::START
          build_client_hello.tap do
            transition_state(State::WAIT_SH)
          end
        when State::WAIT_SEND_FINISHED
          respond_to_finished.tap do
            transition_state(State::CONNECTED)
          end
        end
      ensure
        @buffer = []
      end

      def receive(datagram)
        @receive_buffer += datagram
        buf = ""

        begin
          @received_records = Record.deserialize(@receive_buffer)
        rescue
          return "" # wait desetializable datagram passed
        end
        @receive_buffer = "" # reset buffer if deserialized successfully

        loop do
          pp @state
          received_record = @received_records.shift
          break if received_record.nil?

          records = if received_record.plaintext?
            handle_plaintext_record(received_record)
          else
            handle_ciphertext_record(received_record)
          end

          records.each do |record|
            case record
            when Handshake
              handle_handshake_message(record)
            when Alert
              handle_alert_message(record)
            when ApplicationData
              buf += handle_application_data_message(record)
            else
              pp "Received unknown message: #{record.class}"
            end
          end
        end
        buf
      end

      def handle_handshake_message(handshake)
        case handshake.message
        when Handshake::ServerHello
          receive_server_hello(handshake)
        when Handshake::EncryptedExtensions
          receive_encrypted_extensions(handshake)
        when Handshake::CertificateRequest, Handshake::Certificate
          receive_certificate_or_certificate_request(handshake)
        when Handshake::CertificateVerify
          receive_certificate_verify(handshake)
        when Handshake::Finished
          receive_finished(handshake)
        when Handshake::NewSessionTicket
          receive_new_session_ticket(handshake)
        else
          receive_anything_else(handshake)
        end
      end

      def handle_alert_message(alert)
        pp alert.humanize
      end

      def handle_application_data_message(application_data)
        application_data.content
      end

      # Accepts ServerHello message (or HelloRetryRequest message)
      def receive_server_hello(handshake)
        return unless handshake.message.is_a?(Handshake::ServerHello)

        @server_hello = handshake.message
        @transcript_hash[:server_hello] = handshake.serialize
        if valid_server_hello?
          setup_key_schedule
          setup_cipher
          transition_state(State::WAIT_EE)
        else
          # TODO: error handling
        end
      end

      # Accepts EncryptedExtensions message, if find ChangeCipherSpec message, ignore it
      def receive_encrypted_extensions(handshake)
        # handshakes = Handshake.deserialize_multiple(record.content)
        return unless handshake.message.is_a?(Handshake::EncryptedExtensions)

        encrypted_extensions = handshake.message

        if encrypted_extensions
          @transcript_hash[:encrypted_extensions] = handshake.serialize
          transition_state(State::WAIT_CERT_CR)
          # break
        end
      end

      # Accepts CertificateRequest message or Certificate message
      def receive_certificate_or_certificate_request(handshake)
        return unless handshake.message.is_a?(Handshake::Certificate) ||
                      handshake.message.is_a?(Handshake::CertificateRequest)

        if handshake.message.is_a?(Handshake::Certificate)
          @peer_certificates = handshake.message.certificates
          @transcript_hash[:certificate] = handshake.serialize
          transition_state(State::WAIT_CV)
        elsif handshake.message.is_a?(Handshake::CertificateRequest)
          # TODO:
        end
      end

      # Accepts CertificateVerify message
      def receive_certificate_verify(handshake)
        return unless handshake.message.is_a?(Handshake::CertificateVerify)

        verify_certificate_verify(handshake)
        @transcript_hash[:certificate_verify] = handshake.serialize
        transition_state(State::WAIT_FINISHED)
      end

      def receive_finished(handshake)
        return unless handshake.message.is_a?(Handshake::Finished)

        verify_finished(handshake)
        @transcript_hash[:finished] = handshake.serialize
        derive_application_traffic_secrets
        transition_state(State::WAIT_SEND_FINISHED)
        respond_to_finished
        save_to_sslkeylogfile
        @current_phase = :application
      end

      def receive_new_session_ticket(handshake)
        return unless handshake.message.is_a?(Handshake::NewSessionTicket)

        # Do nothing. raiha client does not support session resumption.
        return
      end

      def receive_anything_else(handshake)
        pp "receive unhandled handshake message: #{handshake.inspect}"
      end

      def build_client_hello
        hs_clienthello = Raiha::TLS::Handshake.new.tap do |hs|
          hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
          hs.message = Raiha::TLS::Handshake::ClientHello.build.tap do |ch|
            if @server_name
              ch.server_name = @server_name
            end
          end
        end
        hs_clienthello.message.setup_key_share(@pkeys)
        @client_hello = hs_clienthello.message
        @transcript_hash.digest_algorithm = @client_hello.cipher_suites.first.hash_algorithm
        @transcript_hash[:client_hello] = hs_clienthello.serialize
        # hs_clienthello.serialize
        Record::TLSPlaintext.serialize(hs_clienthello)
      end

      def respond_to_finished
        finished = Handshake::Finished.new.tap do |fin|
          fin.verify_data = finished_verify_data(@key_schedule.client_handshake_traffic_secret)
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
        @client_cipher.reset_sequence_number
        @server_cipher.reset_sequence_number
        [ciphertext.serialize]
      end

      def finished?
        @state == State::CONNECTED
      end

      def encrypt_application_data(data)
        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = ApplicationData.new.tap do |appdata|
            appdata.content = data
          end.serialize
          inner.content_type = Record::CONTENT_TYPE[:application_data]
        end
        ciphertext = @client_cipher.encrypt(plaintext: innerplaintext, phase: :application)
        ciphertext.serialize
      end

      def receive_application_data
        loop do
          received = @received.shift
          break if received.nil?

          next if received.plaintext?

          inner_plaintext = @server_cipher.decrypt(ciphertext: received, phase: :application)
          inner_plaintext.content
        end
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
        elsif @state == State::WAIT_FINISHED && state == State::WAIT_SEND_FINISHED
          @state = state
        elsif @state == State::WAIT_SEND_FINISHED && state == State::CONNECTED
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
        @key_schedule.derive_secret(secret: :early_secret, label: "derived", transcript_hash: @transcript_hash.empty_digest)
        @key_schedule.derive_client_handshake_traffic_secret(@transcript_hash.hash)
        @key_schedule.derive_server_handshake_traffic_secret(@transcript_hash.hash)
      end

      private def setup_cipher
        @server_cipher = AEAD.new(cipher_suite: @server_hello.cipher_suite, key_schedule: @key_schedule, mode: :server)
        @client_cipher = AEAD.new(cipher_suite: @server_hello.cipher_suite, key_schedule: @key_schedule, mode: :client)
      end

      private def verify_certificate_verify(certificate_verify)
        raise unless certificate_verify.message.verify_signature(
          @peer_certificates.first, # TODO: Check certificate common name
          @transcript_hash.hash,
          "TLS 1.3, server CertificateVerify"
        )
      end

      private def verify_finished(finished)
        # CryptoUtil.hkdf_expand_label("secret", "finished", context, length)
        # finished_key  = @key_schedule.hkdf_expand()
        raise unless finished.message.verify_data == finished_verify_data(@key_schedule.server_handshake_traffic_secret)
      end

      private def derive_application_traffic_secrets
        @key_schedule.derive_client_application_traffic_secret(@transcript_hash.hash)
        @key_schedule.derive_server_application_traffic_secret(@transcript_hash.hash)
      end

      private def finished_verify_data(key)
        # TODO: don't hardcode hash algorithm
        finished_key = CryptoUtil.hkdf_expand_label(key, "finished", "", OpenSSL::Digest.new("sha256").digest_length)
        OpenSSL::HMAC.digest("sha256", finished_key, @transcript_hash.hash)
      end

      private def handle_plaintext_record(record)
        if record.handshake?
          [record.fragment]
        else
          # TODO: maybe alert
          []
        end
      end

      private def handle_ciphertext_record(record)
        inner_plaintext = @server_cipher.decrypt(ciphertext: record, phase: @current_phase)
        if inner_plaintext.handshake?
          Handshake.deserialize_multiple(inner_plaintext.content)
        elsif inner_plaintext.application_data?
          [ApplicationData.deserialize(inner_plaintext.content)]
        elsif inner_plaintext.alert?
          [Alert.deserialize(inner_plaintext.content)]
        else
          []
        end
      end

      private def save_to_sslkeylogfile
        body = <<~SSLKEYLOGFILE
          SERVER_HANDSHAKE_TRAFFIC_SECRET #{@client_hello.random.unpack1("H*")} #{@key_schedule.server_handshake_traffic_secret.unpack1("H*")}
          SERVER_TRAFFIC_SECRET_0 #{@client_hello.random.unpack1("H*")} #{@key_schedule.server_application_traffic_secret[0].unpack1("H*")}
          CLIENT_HANDSHAKE_TRAFFIC_SECRET #{@client_hello.random.unpack1("H*")} #{@key_schedule.client_handshake_traffic_secret.unpack1("H*")}
          CLIENT_TRAFFIC_SECRET_0 #{@client_hello.random.unpack1("H*")} #{@key_schedule.client_application_traffic_secret[0].unpack1("H*")}
        SSLKEYLOGFILE

        File.open("SSLKEYLOGFILE", "a") do |f|
          f.write(body)
        end
      end
    end
  end
end
