# frozen_string_literal: true

require_relative "error"
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

      attr_reader :client_hello
      attr_reader :early_data_available
      attr_reader :received_early_data
      attr_writer :session_ticket_store

      def initialize(config: Config.server_default)
        @config = config
        @state = State::START
        @cipher_suite = nil
        @client_hello = nil
        @server_hello = nil
        @buffer = [] #: Array[String]
        @received = [] #: Array[Record::TLSPlaintext | Record::TLSCiphertext]
        @extensions = {} #: Hash[Symbol, Handshake::Extension::AbstractExtension]
        @key_schedule = KeySchedule.new(mode: :server)
        @transcript_hash = TranscriptHash.new
        @server_certificate = @config.server_certificate
        @server_private_key = @config.server_private_key
        @client_auth_required = @config.request_client_certificate || false
        @session_ticket_store = SessionTicketStore.new
        @psk_mode = false
        @selected_psk = nil
        @early_data_available = false
        @additional_extensions = []
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
          # RFC 8446 §4.5: when 0-RTT was accepted the client transmits
          # EndOfEarlyData under the early-data cipher right before the
          # handshake-encrypted Finished. Drain those records first so
          # the cipher rolls over before receive_finished hits the
          # handshake-phase records.
          receive_early_data if @early_cipher
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
        # @type var empty_buffer: Array[String]
        empty_buffer = []
        @buffer = empty_buffer
      end

      def receive_client_hello
        loop do
          received = @received.shift
          break if received.nil?

          if received.plaintext? && received.handshake? && received.fragment.message.is_a?(Handshake::ClientHello)
            raw_bytes = received.handshake_raw_bytes
            raise Raiha::TLS::Error, "ClientHello without raw_bytes" if raw_bytes.nil?
            @client_hello = received.fragment.message
            @transcript_hash[:client_hello] = raw_bytes
            verify_transcript_roundtrip!(received.fragment, raw_bytes)
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
          raise Raiha::TLS::Error, "No supported group found in client hello"
        end
      end

      def select_parameters
        raise unless @client_hello

        unless choose_cipher_suite
          raise Raiha::TLS::Error, "TODO: alert? cannot choose cipher suite"
        end

        check_psk
        check_early_data
        choose_group
        check_key_share_or_retry

        # If the same datagram included 0-RTT app data (raiha pipelines
        # ClientHello + 0-RTT into one buffer for tests; QUIC packets
        # arrive separately at the QUIC layer), drain it now so callers
        # can observe @received_early_data right after select_parameters.
        receive_early_data if @early_cipher
      end

      # RFC 8446 §4.2.10 / RFC 9001 §4.1.4: accept early data when we
      # just accepted a PSK and the client included the EarlyData
      # extension. Derive the client_early_traffic_secret from the PSK
      # and the ClientHello-only transcript so a QUIC adapter can
      # install 0-RTT AEAD keys.
      private def check_early_data
        return unless @psk_mode

        early_data_ext = @extensions[:client_hello].find do |ext|
          ext.is_a?(Handshake::Extension::EarlyData)
        end
        return unless early_data_ext
        return unless early_data_replay_safe?

        @key_schedule.cipher_suite = @cipher_suite # steep:ignore
        @key_schedule.psk = @selected_psk[:psk] # steep:ignore
        @key_schedule.derive_client_early_traffic_secret(@transcript_hash.hash)

        @early_data_available = true
        @early_data_extension = Handshake::Extension::EarlyData.new(on: :encrypted_extensions)
        @session_ticket_store.mark_consumed_for_early_data(@selected_psk[:ticket]) # steep:ignore

        # Decrypt-only AEAD for inbound 0-RTT records. Encrypt mode is
        # never used on the server but :client picks the
        # client_early_write_{key,iv} we just derived.
        @early_cipher = AEAD.new(cipher_suite: @cipher_suite, key_schedule: @key_schedule, mode: :client) # steep:ignore
      end

      # Drain any 0-RTT records waiting in @received and concatenate
      # ApplicationData payloads into @received_early_data. Stops on
      # EndOfEarlyData, which retires the early cipher.
      private def receive_early_data
        loop do
          record = @received.shift
          break if record.nil?
          next if record.plaintext? && record.change_cipher_spec?

          inner_plaintext = @early_cipher.decrypt(ciphertext: record, phase: :early) # steep:ignore
          if inner_plaintext.application_data?
            @received_early_data ||= String.new(encoding: "BINARY")
            @received_early_data << ApplicationData.deserialize(inner_plaintext.content).content # steep:ignore
          elsif inner_plaintext.handshake?
            Handshake.deserialize_multiple_with_bytes(inner_plaintext.content).each do |hs, raw_bytes|
              next unless hs.message.is_a?(Handshake::EndOfEarlyData)
              @transcript_hash[:end_of_early_data] = raw_bytes
              verify_transcript_roundtrip!(hs, raw_bytes)
              @early_cipher = nil
            end
            break if @early_cipher.nil?
          end
        end
      end

      def psk_mode?
        @psk_mode
      end

      # RFC 9001 §5.1 / RFC 8446 §8: 0-RTT replay defenses. A ticket is
      # treated as single-use for early data, and the client-claimed
      # ticket age must fall within a small window of how long the
      # server has actually held the ticket. Returns false when either
      # check fails so check_early_data leaves @early_data_available
      # cleared (the connection still PSK-resumes without 0-RTT).
      private def early_data_replay_safe?
        return false unless @selected_psk
        ticket = @selected_psk[:ticket] # steep:ignore
        return false if ticket.nil?
        return false if @session_ticket_store.consumed_for_early_data?(ticket)

        within_age_window?
      end

      private def within_age_window?
        psk = @selected_psk
        return false unless psk

        received_at = psk[:received_at] # steep:ignore
        age_add = psk[:age_add] # steep:ignore
        obfuscated = psk[:obfuscated_ticket_age] # steep:ignore
        return false if received_at.nil? || age_add.nil? || obfuscated.nil?

        claimed_age_ms = (obfuscated - age_add) & 0xFFFFFFFF
        actual_age_ms = ((Time.now - received_at) * 1000).to_i
        # RFC 8446 §8.2: a 10-second window is suggested; use it both
        # ways to tolerate clock skew on the client.
        (claimed_age_ms - actual_age_ms).abs <= 10_000
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
            @selected_psk = {
              index: index,
              psk: psk_entry[:psk],
              ticket: psk_entry[:ticket],
              received_at: psk_entry[:received_at],
              age_add: psk_entry[:age_add],
              obfuscated_ticket_age: identity.obfuscated_ticket_age,
            }
            return
          end
        end
      end

      private def verify_psk_binder(psk, binder, identity_index)
        hash_alg = @cipher_suite.hash_algorithm

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
        cr_bytes = handshake.serialize
        @transcript_hash[:certificate_request] = cr_bytes
        verify_transcript_roundtrip!(handshake, cr_bytes)
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
        hrr_bytes = handshake.serialize
        @transcript_hash[:server_hello] = hrr_bytes
        verify_transcript_roundtrip!(handshake, hrr_bytes)

        Record::TLSPlaintext.serialize(handshake)
      end

      private def receive_retry_client_hello
        loop do
          received = @received.shift
          break if received.nil?

          if received.plaintext? && received.handshake? && received.fragment.message.is_a?(Handshake::ClientHello)
            raw_bytes = received.handshake_raw_bytes
            raise Raiha::TLS::Error, "ClientHello (retry) without raw_bytes" if raw_bytes.nil?
            @client_hello = received.fragment.message
            @transcript_hash[:client_hello_retry] = raw_bytes
            verify_transcript_roundtrip!(received.fragment, raw_bytes)
            @extensions[:client_hello] = received.fragment.message.extensions
            transition_state(State::RECVD_CH)
            break
          end
        end
      end

      def build_new_session_ticket(application_data: nil)
        handshake = build_new_session_ticket_handshake(application_data: application_data)

        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = handshake.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        @server_cipher.encrypt(plaintext: innerplaintext, phase: :application).serialize
      end

      # Build a NewSessionTicket Handshake message (without the TLS record
      # wrapping). QUIC carries handshake messages in CRYPTO frames so
      # callers can serialize this directly. The ticket is also stored
      # with the optional opaque application_data blob.
      def build_new_session_ticket_handshake(application_data: nil)
        ticket_nonce = SecureRandom.random_bytes(8)
        ticket_data = SecureRandom.random_bytes(32)

        new_session_ticket = Handshake::NewSessionTicket.new
        new_session_ticket.ticket_lifetime = 7200
        new_session_ticket.ticket_age_add = SecureRandom.random_number(0xFFFFFFFF)
        new_session_ticket.ticket_nonce = ticket_nonce
        new_session_ticket.ticket = ticket_data
        # RFC 9001 §4.6.1: when issuing a ticket on a QUIC connection,
        # max_early_data_size MUST be 0xFFFFFFFF if 0-RTT is allowed
        # (and any other value is a connection error). raiha's TLS layer
        # is built into raiha's QUIC implementation, so always advertise
        # the QUIC sentinel.
        early_data_ext = Handshake::Extension::EarlyData.new(on: :new_session_ticket)
        early_data_ext.max_early_data_size = 0xFFFFFFFF
        early_data_ext.context = :new_session_ticket
        new_session_ticket.extensions = [early_data_ext]

        psk = @key_schedule.derive_resumption_psk(ticket_nonce)
        @session_ticket_store.store(ticket_data, new_session_ticket, psk, application_data: application_data)

        handshake = Handshake.new
        handshake.handshake_type = Handshake::HANDSHAKE_TYPE[:new_session_ticket]
        handshake.message = new_session_ticket
        handshake
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
            # Use the cipher suite selected by choose_cipher_suite (server preference),
            # not the first one supported by the client (ServerHello default)
            sh.cipher_suite = @cipher_suite

            additional_extensions = [
              Handshake::Extension::KeyShare.new(on: :server_hello).tap do |ks|
                if @pkey[:group] == "x25519"
                  ks.groups = [{ group: @pkey[:group], key_exchange: @pkey[:pkey].raw_public_key }]
                elsif @pkey[:group] == "prime256v1"
                  ks.groups = [{ group: @pkey[:group], key_exchange: @pkey[:pkey].public_key.to_octet_string(:uncompressed) }]
                else
                  raise Raiha::TLS::Error, "TODO: #{@pkey[:group]}"
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
        sh_bytes = handshake.serialize
        @transcript_hash[:server_hello] = sh_bytes
        verify_transcript_roundtrip!(handshake, sh_bytes)
        @server_hello = handshake.message
        setup_key_schedule
        setup_cipher
        Record::TLSPlaintext.serialize(handshake)
      end

      def build_encrypted_extensions
        handshake = Handshake.new.tap do |hs|
          hs.handshake_type = Handshake::HANDSHAKE_TYPE[:encrypted_extensions]
          hs.message = Handshake::EncryptedExtensions.new.tap do |ee|
            extensions = [
              Handshake::Extension::SupportedGroups.new(on: :encrypted_extensions).tap do |sg|
                sg.groups = [@pkey[:group]]
              end,
              *@additional_extensions
            ]
            # RFC 8446 §4.2.10: echo EarlyData in EncryptedExtensions so
            # the client knows 0-RTT was accepted.
            extensions << @early_data_extension if @early_data_extension
            ee.extensions = extensions
          end
        end
        ee_bytes = handshake.serialize
        @transcript_hash[:encrypted_extensions] = ee_bytes
        verify_transcript_roundtrip!(handshake, ee_bytes)
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
        cert_bytes = handshake.serialize
        @transcript_hash[:certificate] = cert_bytes
        verify_transcript_roundtrip!(handshake, cert_bytes)
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
            # cv.sign picks the signature_scheme from the private key
            # type (RSA-PSS for RSA, ECDSA for EC), so leave algorithm
            # unset here — sign assigns it.
            cv.sign(@server_private_key, @transcript_hash.hash, "TLS 1.3, server CertificateVerify")
          end
        end
        cv_bytes = handshake.serialize
        @transcript_hash[:certificate_verify] = cv_bytes
        verify_transcript_roundtrip!(handshake, cv_bytes)
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
            fin.verify_data = @key_schedule.finished_verify_data(@transcript_hash.hash, from: :server)
          end
        end

        fin_bytes = handshake.serialize
        @transcript_hash[:finished] = fin_bytes
        verify_transcript_roundtrip!(handshake, fin_bytes)
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
          Handshake.deserialize_multiple_with_bytes(inner_plaintext.content).each do |hs, raw_bytes|
            handle_handshake_message(hs, raw_bytes)
          end
        end
      end

      def handle_handshake_message(handshake, raw_bytes)
        case handshake.message
        when Handshake::Certificate
          receive_client_certificate(handshake, raw_bytes)
        when Handshake::CertificateVerify
          receive_client_certificate_verify(handshake, raw_bytes)
        when Handshake::Finished
          receive_client_finished(handshake, raw_bytes)
        end
      end

      def receive_client_certificate(handshake, raw_bytes)
        return unless handshake.message.is_a?(Handshake::Certificate)

        @client_certificates = handshake.message.certificates
      end

      def receive_client_certificate_verify(handshake, raw_bytes)
        return unless handshake.message.is_a?(Handshake::CertificateVerify)

        if @client_certificates&.any?
          raise unless handshake.message.verify_signature(
            @client_certificates.first,
            @transcript_hash.hash,
            "TLS 1.3, client CertificateVerify"
          )
        end
      end

      def receive_client_finished(handshake, raw_bytes)
        return unless handshake.message.is_a?(Handshake::Finished)

        verify_finished(handshake)
        @key_schedule.derive_resumption_master_secret(@transcript_hash.hash)
        transition_state(State::CONNECTED)
        @server_cipher.reset_sequence_number
        @client_cipher.reset_sequence_number
      end

      def connected?
        @state == State::CONNECTED
      end

      # Peer hooks
      def negotiated_cipher_suite
        @cipher_suite
      end

      def own_cipher
        @server_cipher
      end

      def peer_cipher
        @client_cipher
      end

      # Verify a client Finished handshake message against the current transcript.
      # Returns true on success, raises on mismatch. Safe to call repeatedly.
      def verify_client_finished(handshake)
        return false unless @key_schedule && @server_hello

        expected = @key_schedule.finished_verify_data(@transcript_hash.hash, from: :client)
        unless handshake.message.verify_data == expected
          raise Raiha::TLS::Error, "Client Finished verification failed"
        end
        @key_schedule.derive_resumption_master_secret(@transcript_hash.hash)
        save_to_sslkeylogfile
        true
      end

      # Append the negotiated traffic secrets to the file pointed to by
      # the SSLKEYLOGFILE environment variable so external tooling
      # (Wireshark, packet decoders) can decrypt captured traffic.
      # Silently no-ops when the env var is unset.
      private def save_to_sslkeylogfile
        path = ENV["SSLKEYLOGFILE"]
        return unless path && !path.empty?
        return unless @client_hello && @key_schedule

        client_random = @client_hello.random.unpack1("H*")
        body = <<~SSLKEYLOGFILE
          SERVER_HANDSHAKE_TRAFFIC_SECRET #{client_random} #{@key_schedule.server_handshake_traffic_secret.unpack1("H*")}
          SERVER_TRAFFIC_SECRET_0 #{client_random} #{@key_schedule.server_application_traffic_secret[0].unpack1("H*")}
          CLIENT_HANDSHAKE_TRAFFIC_SECRET #{client_random} #{@key_schedule.client_handshake_traffic_secret.unpack1("H*")}
          CLIENT_TRAFFIC_SECRET_0 #{client_random} #{@key_schedule.client_application_traffic_secret[0].unpack1("H*")}
        SSLKEYLOGFILE

        File.open(path, "a") do |f|
          f.write(body)
        end
      end

      # Return the concatenated raw handshake bytes for the server flight at the
      # given encryption level, or nil if there is nothing yet. Used by QUIC
      # to queue CRYPTO data at the right level.
      #   :initial    => ServerHello
      #   :handshake  => EncryptedExtensions + Certificate + CertificateVerify + Finished
      def response_flight_bytes(level)
        case level
        when :initial
          @transcript_hash[:server_hello]
        when :handshake
          buf = String.new(encoding: "BINARY")
          [:encrypted_extensions, :certificate, :certificate_verify, :finished].each do |key|
            buf << @transcript_hash[key] if @transcript_hash[key]
          end
          buf.empty? ? nil : buf
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
          raise Raiha::TLS::Error, "Invalid state transition: #{@state} -> #{state}"
        end
      end

      private def setup_key_schedule
        @key_schedule.cipher_suite = @cipher_suite
        @key_schedule.group = @pkey[:group]
        @key_schedule.public_key = @client_hello.key_share.groups.find { |g| g[:group] == @pkey[:group] }[:key_exchange]
        @key_schedule.pkey = @pkey[:pkey]
        @key_schedule.compute_shared_secret
        # PSK resumption: the Early Secret must include the selected PSK
        # so the salt for the Handshake Secret matches the client (RFC
        # 8446 §7.1). check_early_data already set this for the 0-RTT
        # path; resumption without 0-RTT needs it here.
        if @psk_mode && @selected_psk
          @key_schedule.psk = @selected_psk[:psk]
        end
        @key_schedule.derive_secret(secret: :early_secret, label: "derived", transcript_hash: @transcript_hash.empty_digest)
        @key_schedule.derive_client_handshake_traffic_secret(@transcript_hash.hash)
        @key_schedule.derive_server_handshake_traffic_secret(@transcript_hash.hash)
      end

      private def verify_finished(finished)
        raise unless finished.message.verify_data == @key_schedule.finished_verify_data(@transcript_hash.hash, from: :client)
      end
    end
  end
end
