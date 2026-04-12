# frozen_string_literal: true

require_relative "context"
require_relative "peer"
require_relative "record"
require_relative "handshake"
require_relative "key_schedule"
require_relative "aead"
require_relative "transcript_hash"
require_relative "../crypto_util"
require_relative "alert"
require_relative "session_ticket_store"
require "securerandom"

module Raiha
  module TLS
    class Server < Peer
      module State
        START = :START
        RECVD_CH = :RECVD_CH
        NEGOTIATED = :NEGOTIATED
        WAIT_EOED = :WAIT_EOED
        WAIT_FLIGHT2 = :WAIT_FLIGHT2
        WAIT_CERT = :WAIT_CERT
        WAIT_CV = :WAIT_CV
        WAIT_FINISHED = :WAIT_FINISHED
        CONNECTED = :CONNECTED
        WAIT_CH_RETRY = :WAIT_CH_RETRY
        ERROR_OCCURED = :ERROR_OCCURED
      end

      attr_reader :state

      def initialize(config: Config.server_default)
        @config = config
        @state = State::START
        @cipher_suite = nil
        @client_hello = nil
        @server_hello = nil
        @buffer = []
        @received = []
        @extensions = {}
        @key_schedule = KeySchedule.new(mode: :server)
        @transcript_hash = TranscriptHash.new
        @server_certificate = @config.server_certificate
        @server_private_key = @config.server_private_key
        @client_auth_required = @config.request_client_certificate || false
        @session_ticket_store = SessionTicketStore.new
        @psk_mode = false
        @selected_psk = nil
      end

      def receive(datagram)
        @received = Record.deserialize(datagram)

        case @state
        when State::START
          receive_client_hello
          select_parameters
        when State::WAIT_CH_RETRY
          receive_retry_client_hello
          select_parameters
        when State::NEGOTIATED
          receive_finished
        when State::CONNECTED
          receive_application_data
        end
      end

      def datagrams_to_send
        case @state
        when State::RECVD_CH
          if @needs_hello_retry
            @needs_hello_retry = false
            transition_state(State::WAIT_CH_RETRY)
            build_hello_retry_request.flatten
          else
            messages = [
              build_server_hello,
              build_change_cipher_spec,
              build_encrypted_extensions,
            ]
            unless @psk_mode
              messages << build_certificate_request if @client_auth_required
              messages << build_certificate
              messages << build_certificate_verify
            end
            messages << build_finished
            messages.flatten
          end
        when State::ERROR_OCCURED
          @buffer.tap do
            transition_state(State::START)
          end
        else
          # TODO: WIP
        end
      ensure
        @buffer = []
      end

      def receive_client_hello
        loop do
          received = @received.shift
          break if received.nil?

          if received.plaintext? && received.handshake? && received.fragment.message.is_a?(Handshake::ClientHello)
            @client_hello = received.fragment.message
            @transcript_hash[:client_hello] = received.fragment.serialize
            @extensions[:client_hello] = received.fragment.message.extensions
            break
          else
            # TODO: not a client hello
          end
        end
        if @client_hello
          if !@client_hello.valid_legacy_version?
            @buffer << build_error_alert(Alert.new(level: :fatal, description: :illegal_parameter))
            transition_state(State::ERROR_OCCURED)
          else
            # valid client hello
            transition_state(State::RECVD_CH)
          end
        end
      end

      def choose_cipher_suite
        client_suite_names = @client_hello.cipher_suites.select(&:supported?).map(&:name)
        @cipher_suite = @config.cipher_suites.find { |cs| client_suite_names.include?(cs.name) }
        @transcript_hash.digest_algorithm = @cipher_suite.hash_algorithm
      end

      def choose_group
        supported_groups = @extensions[:client_hello].find { |ext| ext.is_a?(Handshake::Extension::SupportedGroups) }
        raise unless supported_groups

        if supported_groups.groups.include?("x25519")
          @pkey = { group: "x25519", pkey: OpenSSL::PKey.generate_key("x25519") }
        elsif supported_groups.groups.include?("prime256v1")
          @pkey = { group: "prime256v1", pkey: OpenSSL::PKey::EC.generate("prime256v1") }
        else
          raise "No supported group found in client hello"
        end
      end

      def select_parameters
        raise unless @client_hello

        unless choose_cipher_suite
          raise "TODO: alert? cannot choose cipher suite"
        end

        check_psk
        choose_group
        check_key_share_or_retry
      end

      private def check_psk
        psk_ext = @extensions[:client_hello].find { |ext| ext.is_a?(Handshake::Extension::PreSharedKey) }
        return unless psk_ext
        return if psk_ext.identities.empty?

        psk_modes_ext = @extensions[:client_hello].find { |ext| ext.is_a?(Handshake::Extension::PskKeyExchangeModes) }
        return unless psk_modes_ext&.modes&.include?(:psk_dhe_ke)

        psk_ext.identities.each_with_index do |identity, index|
          psk_entry = @session_ticket_store.get_by_ticket(identity.identity)
          next unless psk_entry

          if verify_psk_binder(psk_entry[:psk], psk_ext.binders[index], index)
            @psk_mode = true
            @selected_psk = { index: index, psk: psk_entry[:psk] }
            return
          end
        end
      end

      private def verify_psk_binder(psk, binder, identity_index)
        hash_alg = @cipher_suite.hash_algorithm
        digest_length = OpenSSL::Digest.new(hash_alg).digest_length

        # Reconstruct truncated ClientHello for binder verification
        client_hello_serialized = @transcript_hash[:client_hello]
        binders_size = compute_binders_size(identity_index)
        truncated = client_hello_serialized[0...(client_hello_serialized.bytesize - binders_size)]

        expected_binder = compute_psk_binder(psk, truncated, hash_alg)
        binder == expected_binder
      end

      private def compute_binders_size(target_index)
        psk_ext = @extensions[:client_hello].find { |ext| ext.is_a?(Handshake::Extension::PreSharedKey) }
        binder_entries_size = psk_ext.binders.sum { |b| 1 + b.bytesize }
        2 + binder_entries_size # binders_length(2) + all binder entries
      end

      private def compute_psk_binder(psk, truncated_client_hello, hash_alg)
        digest_length = OpenSSL::Digest.new(hash_alg).digest_length

        early_secret = OpenSSL::HMAC.digest(hash_alg, "\x00" * digest_length, psk)
        empty_hash = OpenSSL::Digest.new(hash_alg).digest
        binder_key = CryptoUtil.hkdf_expand_label(early_secret, "res binder", empty_hash, digest_length, hash: hash_alg)
        finished_key = CryptoUtil.hkdf_expand_label(binder_key, "finished", "", digest_length, hash: hash_alg)

        transcript_hash = OpenSSL::Digest.new(hash_alg).digest(truncated_client_hello)
        OpenSSL::HMAC.digest(hash_alg, finished_key, transcript_hash)
      end

      private def check_key_share_or_retry
        client_key_share = @client_hello.key_share
        return unless client_key_share

        has_matching_share = client_key_share.groups.any? { |g| g[:group] == @pkey[:group] }
        unless has_matching_share
          @needs_hello_retry = true
        end
      end

      def build_certificate_request
        handshake = Handshake.new.tap do |hs|
          hs.handshake_type = Handshake::HANDSHAKE_TYPE[:certificate_request]
          hs.message = Handshake::CertificateRequest.new.tap do |cr|
            cr.certificate_request_context = ""
            cr.extensions = [
              Handshake::Extension::SignatureAlgorithms.new(on: :certificate_request).tap do |sa|
                sa.signature_schemes = %w[
                  rsa_pss_rsae_sha256
                  rsa_pss_rsae_sha384
                  rsa_pss_rsae_sha512
                  ecdsa_secp256r1_sha256
                  ecdsa_secp384r1_sha384
                  ecdsa_secp521r1_sha512
                ]
              end
            ]
          end
        end
        @transcript_hash[:certificate_request] = handshake.serialize
        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = handshake.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        @server_cipher.encrypt(plaintext: innerplaintext, phase: :handshake).serialize
      end

      def build_hello_retry_request
        hrr = Handshake::ServerHello.new
        hrr.random = Handshake::ServerHello::HELLO_RETRY_REQUEST_RANDOM
        hrr.legacy_session_id_echo = @client_hello.legacy_session_id
        hrr.cipher_suite = @cipher_suite
        hrr.extensions = [
          Handshake::Extension::SupportedVersions.generate_for_tls13(on: :server_hello),
          Handshake::Extension::KeyShare.new(on: :hello_retry_request).tap do |ks|
            ks.groups = [{ group: @pkey[:group], key_exchange: "" }]
          end
        ]

        handshake = Handshake.new
        handshake.handshake_type = Handshake::HANDSHAKE_TYPE[:server_hello]
        handshake.message = hrr

        # Replace ClientHello1 with message_hash in transcript
        @transcript_hash.replace_client_hello_with_message_hash
        @transcript_hash[:server_hello] = handshake.serialize

        Record::TLSPlaintext.serialize(handshake)
      end

      private def receive_retry_client_hello
        loop do
          received = @received.shift
          break if received.nil?

          if received.plaintext? && received.handshake? && received.fragment.message.is_a?(Handshake::ClientHello)
            @client_hello = received.fragment.message
            @transcript_hash[:client_hello_retry] = received.fragment.serialize
            @extensions[:client_hello] = received.fragment.message.extensions
            transition_state(State::RECVD_CH)
            break
          end
        end
      end

      def build_new_session_ticket
        ticket_nonce = SecureRandom.random_bytes(8)
        ticket_data = SecureRandom.random_bytes(32)

        new_session_ticket = Handshake::NewSessionTicket.new
        new_session_ticket.ticket_lifetime = 7200
        new_session_ticket.ticket_age_add = SecureRandom.random_number(0xFFFFFFFF)
        new_session_ticket.ticket_nonce = ticket_nonce
        new_session_ticket.ticket = ticket_data
        new_session_ticket.extensions = []

        psk = @key_schedule.derive_resumption_psk(ticket_nonce)
        @session_ticket_store.store(ticket_data, new_session_ticket, psk)

        handshake = Handshake.new
        handshake.handshake_type = Handshake::HANDSHAKE_TYPE[:new_session_ticket]
        handshake.message = new_session_ticket

        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = handshake.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        @server_cipher.encrypt(plaintext: innerplaintext, phase: :application).serialize
      end

      def build_change_cipher_spec
        Record::TLSPlaintext.serialize(ChangeCipherSpec.new)
      end

      def build_error_alert(alert)
        Record::TLSPlaintext.serialize(alert)
      end

      def build_server_hello
        handshake = Handshake.new.tap do |hs|
          hs.handshake_type = Handshake::HANDSHAKE_TYPE[:server_hello]
          hs.message = Handshake::ServerHello.build_from_client_hello(@client_hello).tap do |sh|
            additional_extensions = [
              Handshake::Extension::KeyShare.new(on: :server_hello).tap do |ks|
                if @pkey[:group] == "x25519"
                  ks.groups = [{ group: @pkey[:group], key_exchange: @pkey[:pkey].raw_public_key }]
                elsif @pkey[:group] == "prime256v1"
                  ks.groups = [{ group: @pkey[:group], key_exchange: @pkey[:pkey].public_key.to_octet_string(:uncompressed) }]
                else
                  raise "TODO: #{@pkey[:group]}"
                end
              end
            ]

            if @psk_mode && @selected_psk
              additional_extensions << Handshake::Extension::PreSharedKey.new(on: :server_hello).tap do |psk|
                psk.selected_identity = @selected_psk[:index]
              end
            end

            sh.extensions += additional_extensions
          end
        end
        @transcript_hash[:server_hello] = handshake.serialize
        @server_hello = handshake.message
        setup_key_schedule
        setup_cipher
        Record::TLSPlaintext.serialize(handshake)
      end

      def build_encrypted_extensions
        handshake = Handshake.new.tap do |hs|
          hs.handshake_type = Handshake::HANDSHAKE_TYPE[:encrypted_extensions]
          hs.message = Handshake::EncryptedExtensions.new.tap do |ee|
            ee.extensions = [
              Handshake::Extension::SupportedGroups.new(on: :encrypted_extensions).tap do |sg|
                sg.groups = [@pkey[:group]]
              end
            ]
          end
        end
        @transcript_hash[:encrypted_extensions] = handshake.serialize
        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = handshake.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        ciphertext = @server_cipher.encrypt(plaintext: innerplaintext, phase: :handshake)
        ciphertext.serialize
      end

      def build_certificate
        handshake = Handshake.new.tap do |hs|
          hs.handshake_type = Handshake::HANDSHAKE_TYPE[:certificate]
          hs.message = Handshake::Certificate.new.tap do |cert|
            cert.certificate_entries << Handshake::Certificate::CertificateEntry.new(
              opaque_certificate_data: @server_certificate.to_der,
              extensions: []
            )
          end
        end
        @transcript_hash[:certificate] = handshake.serialize
        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = handshake.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        @server_cipher.encrypt(plaintext: innerplaintext, phase: :handshake).serialize
      end

      def build_certificate_verify
        handshake = Handshake.new.tap do |hs|
          hs.handshake_type = Handshake::HANDSHAKE_TYPE[:certificate_verify]
          hs.message = Handshake::CertificateVerify.new.tap do |cv|
            cv.algorithm = "rsa_pss_rsae_sha256"
            cv.sign(@server_private_key, @transcript_hash.hash, "TLS 1.3, server CertificateVerify")
          end
        end
        @transcript_hash[:certificate_verify] = handshake.serialize
        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = handshake.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        @server_cipher.encrypt(plaintext: innerplaintext, phase: :handshake).serialize
      end

      def build_finished
        handshake = Handshake.new.tap do |hs|
          hs.handshake_type = Handshake::HANDSHAKE_TYPE[:finished]
          hs.message = Handshake::Finished.new.tap do |fin|
            fin.verify_data = finished_verify_data(@key_schedule.server_handshake_traffic_secret)
          end
        end

        @transcript_hash[:finished] = handshake.serialize
        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = handshake.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        transition_state(State::NEGOTIATED)
        derive_application_traffic_secrets
        @server_cipher.encrypt(plaintext: innerplaintext, phase: :handshake).serialize
      end

      def receive_finished
        loop do
          received = @received.shift
          break if received.nil?
          break if connected?

          next if received.plaintext? && received.change_cipher_spec?
          inner_plaintext = @client_cipher.decrypt(ciphertext: received, phase: :handshake)
          messages = Handshake.deserialize_multiple(inner_plaintext.content)

          messages.each do |hs|
            case hs.message
            when Handshake::Certificate
              @client_certificates = hs.message.certificates
            when Handshake::CertificateVerify
              if @client_certificates&.any?
                raise unless hs.message.verify_signature(
                  @client_certificates.first,
                  @transcript_hash.hash,
                  "TLS 1.3, client CertificateVerify"
                )
              end
            when Handshake::Finished
              verify_finished(hs)
              @key_schedule.derive_resumption_master_secret(@transcript_hash.hash)
              transition_state(State::CONNECTED)
              @server_cipher.reset_sequence_number
              @client_cipher.reset_sequence_number
            end
          end
        end
      end

      def connected?
        @state == State::CONNECTED
      end

      def encrypt_application_data(data)
        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = ApplicationData.new.tap do |appdata|
            appdata.content = data
          end.serialize
          inner.content_type = Record::CONTENT_TYPE[:application_data]
        end
        ciphertext = @server_cipher.encrypt(plaintext: innerplaintext, phase: :application)
        ciphertext.serialize
      end

      def receive_application_data
        loop do
          received = @received.shift
          break if received.nil?

          next if received.plaintext?

          inner_plaintext = @client_cipher.decrypt(ciphertext: received, phase: :application)
          # TODO: handle received application data
        end
      end

      private def transition_state(state)
        if state == State::ERROR_OCCURED || @state == State::ERROR_OCCURED
          @state = state
          return
        end

        if @state == State::START && state == State::RECVD_CH
          @state = state
        elsif @state == State::RECVD_CH && state == State::WAIT_CH_RETRY
          @state = state
        elsif @state == State::WAIT_CH_RETRY && state == State::RECVD_CH
          @state = state
        elsif @state == State::RECVD_CH && state == State::NEGOTIATED
          @state = state
        elsif @state == State::NEGOTIATED && state == State::CONNECTED
          @state = state
        else
          raise "Invalid state transition: #{@state} -> #{state}"
        end
      end

      private def setup_key_schedule
        @key_schedule.cipher_suite = @cipher_suite
        @key_schedule.group = @pkey[:group]
        @key_schedule.public_key = @client_hello.key_share.groups.find { |g| g[:group] == @pkey[:group] }[:key_exchange]
        @key_schedule.pkey = @pkey[:pkey]
        @key_schedule.compute_shared_secret
        @key_schedule.derive_secret(secret: :early_secret, label: "derived", transcript_hash: @transcript_hash.empty_digest)
        @key_schedule.derive_client_handshake_traffic_secret(@transcript_hash.hash)
        @key_schedule.derive_server_handshake_traffic_secret(@transcript_hash.hash)
      end

      private def setup_cipher
        @server_cipher = AEAD.new(cipher_suite: @cipher_suite, key_schedule: @key_schedule, mode: :server)
        @client_cipher = AEAD.new(cipher_suite: @cipher_suite, key_schedule: @key_schedule, mode: :client)
      end

      private def finished_verify_data(key)
        hash_alg = @cipher_suite.hash_algorithm
        finished_key = CryptoUtil.hkdf_expand_label(key, "finished", "", OpenSSL::Digest.new(hash_alg).digest_length, hash: hash_alg)
        OpenSSL::HMAC.digest(hash_alg, finished_key, @transcript_hash.hash)
      end

      private def verify_finished(finished)
        raise unless finished.message.verify_data == finished_verify_data(@key_schedule.client_handshake_traffic_secret)
      end

      private def derive_application_traffic_secrets
        @key_schedule.derive_client_application_traffic_secret(@transcript_hash.hash)
        @key_schedule.derive_server_application_traffic_secret(@transcript_hash.hash)
      end
    end
  end
end
