# frozen_string_literal: true

require_relative "alert"
require_relative "application_data"
require_relative "config"
require_relative "error"
require_relative "peer"
require_relative "record"
require_relative "handshake"
require_relative "key_schedule"
require_relative "aead"
require_relative "transcript_hash"
require_relative "../crypto_util"
require_relative "session_ticket_store"

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
        WAIT_SH_RETRY = :WAIT_SH_RETRY
        ERROR = :ERROR
        CLOSED = :CLOSED
      end

      attr_reader :encrypted_extensions
      attr_reader :client_hello
      attr_reader :early_data_available
      attr_writer :session_ticket_store

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
        @pkeys = @groups.map { |group| { group: group, pkey: generate_pkey(group) } }
        @server_cipher = nil
        @client_cipher = nil
        @current_phase = :handshake
        @server_name = server_name
        @close_notify_sent = false
        @client_auth_required = false
        @certificate_request = nil
        @session_ticket_store = SessionTicketStore.new
        @early_data_available = false
        @early_cipher = nil
        @additional_extensions = []
      end

      def datagrams_to_send
        case @state
        when State::START
          build_client_hello.tap do
            transition_state(State::WAIT_SH)
          end
        when State::WAIT_SH_RETRY
          @retry_client_hello_record.tap do
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
        when Handshake::KeyUpdate
          receive_key_update(handshake)
        else
          receive_anything_else(handshake)
        end
      end

      def handle_alert_message(alert)
        if alert.fatal?
          @state = State::ERROR
        end

        case alert.description
        when :close_notify
          @buffer.concat(send_alert(:warning, :close_notify)) unless @close_notify_sent
          @state = State::CLOSED
        end
      end

      def handle_application_data_message(application_data)
        application_data.content
      end

      # Accepts ServerHello message (or HelloRetryRequest message)
      def receive_server_hello(handshake)
        return unless handshake.message.is_a?(Handshake::ServerHello)

        if handshake.message.hello_retry_request?
          receive_hello_retry_request(handshake)
        else
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
      end

      def receive_hello_retry_request(handshake)
        hrr = handshake.message

        # Replace ClientHello1 with message_hash in transcript
        @transcript_hash.replace_client_hello_with_message_hash
        @transcript_hash[:server_hello] = handshake.serialize

        # Rebuild ClientHello with requested key share group
        requested_group = hrr.key_share&.groups&.first&.dig(:group)
        rebuild_client_hello_for_retry(hrr, requested_group: requested_group)

        transition_state(State::WAIT_SH_RETRY)
      end

      # RFC 8446 §4.2.10: the server signals 0-RTT acceptance by echoing
      # the EarlyData extension in EncryptedExtensions. Returns nil while
      # we have not yet processed EE.
      def early_data_accepted?
        ee = @encrypted_extensions
        return nil unless ee
        ee.extensions.any? { |ext| ext.is_a?(Handshake::Extension::EarlyData) }
      end

      # True once a server Certificate has been received and stored. PSK
      # resumption skips Certificate entirely, so callers can use this to
      # tell whether the peer was authenticated via X.509 in this handshake.
      def peer_authenticated?
        !!(@peer_certificates && !@peer_certificates.empty?)
      end

      # Accepts EncryptedExtensions message, if find ChangeCipherSpec message, ignore it
      def receive_encrypted_extensions(handshake)
        # handshakes = Handshake.deserialize_multiple(record.content)
        return unless handshake.message.is_a?(Handshake::EncryptedExtensions)

        encrypted_extensions = handshake.message

        if encrypted_extensions
          @encrypted_extensions = encrypted_extensions
          @transcript_hash[:encrypted_extensions] = handshake.serialize
          # RFC 8446 §2.2 / §4.1.1: when the server selected our PSK,
          # Certificate/CertificateVerify are skipped — go straight to
          # waiting for the server Finished.
          if psk_mode?
            transition_state(State::WAIT_FINISHED)
          else
            transition_state(State::WAIT_CERT_CR)
          end
        end
      end

      # Accepts CertificateRequest message or Certificate message
      def receive_certificate_or_certificate_request(handshake)
        return unless handshake.message.is_a?(Handshake::Certificate) ||
                      handshake.message.is_a?(Handshake::CertificateRequest)

        if handshake.message.is_a?(Handshake::CertificateRequest)
          @certificate_request = handshake.message
          @transcript_hash[:certificate_request] = handshake.serialize
          @client_auth_required = true
          transition_state(State::WAIT_CERT)
        elsif handshake.message.is_a?(Handshake::Certificate)
          @peer_certificates = handshake.message.certificates
          @transcript_hash[:certificate] = handshake.serialize
          transition_state(State::WAIT_CV)
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
        @key_schedule.derive_resumption_master_secret(@transcript_hash.hash)
        transition_state(State::WAIT_SEND_FINISHED)
        save_to_sslkeylogfile
        @current_phase = :application
      end

      def receive_new_session_ticket(handshake)
        return unless handshake.message.is_a?(Handshake::NewSessionTicket)

        new_session_ticket = handshake.message
        psk = @key_schedule.derive_resumption_psk(new_session_ticket.ticket_nonce)
        @session_ticket_store&.store(@server_name || "", new_session_ticket, psk)
      end

      def receive_key_update(handshake)
        return unless handshake.message.is_a?(Handshake::KeyUpdate)

        key_update = handshake.message

        # Update the server (peer) application traffic secret and reset sequence number
        @key_schedule.update_server_application_traffic_secret
        @server_cipher.reset_sequence_number

        # If the server requested an update, respond with our own KeyUpdate
        if key_update.request_update == :update_requested
          @buffer.concat(send_key_update(request_update: :update_not_requested))
        end
      end

      def send_key_update(request_update: :update_not_requested)
        key_update = Handshake::KeyUpdate.new
        key_update.request_update = request_update

        hs = Handshake.new
        hs.handshake_type = Handshake::HANDSHAKE_TYPE[:key_update]
        hs.message = key_update

        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = hs.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        ciphertext = @client_cipher.encrypt(plaintext: innerplaintext, phase: :application)

        # Update our own application traffic secret and reset sequence number
        @key_schedule.update_client_application_traffic_secret
        @client_cipher.reset_sequence_number

        [ciphertext.serialize]
      end

      def send_alert(level, description)
        alert = Alert.new(level: level, description: description)
        @close_notify_sent = true if description == :close_notify

        if @client_cipher
          innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
            inner.content = alert.serialize
            inner.content_type = Record::CONTENT_TYPE[:alert]
          end
          ciphertext = @client_cipher.encrypt(plaintext: innerplaintext, phase: :application)
          [ciphertext.serialize]
        else
          Record::TLSPlaintext.serialize(alert)
        end
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
        @additional_extensions.each { |ext| hs_clienthello.message.extensions << ext }
        @client_hello = hs_clienthello.message
        @transcript_hash.digest_algorithm = @client_hello.cipher_suites.first.hash_algorithm

        psk_entry = @session_ticket_store.get(@server_name || "")
        if psk_entry
          # RFC 8446 §4.2.10 / RFC 9001 §4.6.1: 0-RTT requires the issuing
          # ticket to advertise EarlyData. RFC 8446 §4.2.11 also forces
          # PreSharedKey to be the last extension in ClientHello, so add
          # EarlyData first and let add_psk_to_client_hello append PSK at
          # the very end (otherwise the binder is computed over the wrong
          # bytes and the server rejects the PSK).
          if ticket_allows_early_data?(psk_entry)
            @client_hello.extensions << Handshake::Extension::EarlyData.new(on: :client_hello)
            @early_data_available = true
          end
          add_psk_to_client_hello(hs_clienthello, psk_entry)
        end

        @transcript_hash[:client_hello] = hs_clienthello.serialize

        if @early_data_available
          setup_early_data_cipher(psk_entry)
        end

        Record::TLSPlaintext.serialize(hs_clienthello)
      end

      def send_early_data(data)
        return nil unless @early_data_available && @early_cipher

        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = ApplicationData.new.tap { |appdata| appdata.content = data }.serialize
          inner.content_type = Record::CONTENT_TYPE[:application_data]
        end
        ciphertext = @early_cipher.encrypt(plaintext: innerplaintext, phase: :early)
        ciphertext.serialize
      end

      def send_end_of_early_data
        return nil unless @early_data_available

        @early_data_available = false

        handshake = Handshake.new
        handshake.handshake_type = Handshake::HANDSHAKE_TYPE[:end_of_early_data]
        handshake.message = Handshake::EndOfEarlyData.new

        # RFC 8446 §4.5: EndOfEarlyData is folded into the handshake
        # transcript before client Finished is computed, so record it
        # here even though it travels under the 0-RTT cipher.
        @transcript_hash[:end_of_early_data] = handshake.serialize

        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = handshake.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        ciphertext = @early_cipher.encrypt(plaintext: innerplaintext, phase: :early)
        ciphertext.serialize
      end

      private def setup_early_data_cipher(psk_entry)
        cipher_suite = @client_hello.cipher_suites.first

        # Set cipher suite on key_schedule so hash_algorithm is available
        @key_schedule.cipher_suite = cipher_suite

        # Hand the PSK to the key schedule so derive_secret(:early_secret)
        # computes the Early Secret from the PSK (RFC 8446 §7.1).
        @key_schedule.psk = psk_entry[:psk]

        # Derive client_early_traffic_secret
        @key_schedule.derive_client_early_traffic_secret(@transcript_hash.hash)

        # Create early data cipher
        @early_cipher = AEAD.new(cipher_suite: cipher_suite, key_schedule: @key_schedule, mode: :client)
      end

      private def ticket_allows_early_data?(psk_entry)
        extensions = psk_entry[:extensions]
        return false unless extensions

        extensions.any? { |ext| ext.is_a?(Handshake::Extension::EarlyData) }
      end

      private def add_psk_to_client_hello(hs_clienthello, psk_entry)
        client_hello = hs_clienthello.message

        # Add PskKeyExchangeModes extension
        client_hello.extensions << Handshake::Extension::PskKeyExchangeModes.new(on: :client_hello).tap do |modes|
          modes.modes = [:psk_dhe_ke]
        end

        # Build PreSharedKey extension with placeholder binder
        hash_alg = client_hello.cipher_suites.first.hash_algorithm
        binder_length = OpenSSL::Digest.new(hash_alg).digest_length

        ticket_age = ((Time.now - psk_entry[:received_at]) * 1000).to_i + psk_entry[:age_add]
        psk_ext = Handshake::Extension::PreSharedKey.new(on: :client_hello)
        psk_ext.identities = [
          Handshake::Extension::PreSharedKey::PskIdentity.new(psk_entry[:ticket], ticket_age & 0xFFFFFFFF)
        ]
        psk_ext.binders = ["\x00" * binder_length]
        client_hello.extensions << psk_ext

        # Compute binder over truncated ClientHello (everything except the binder values)
        serialized = hs_clienthello.serialize
        binders_size = 2 + 1 + binder_length # binders_length(2) + binder_entry_length(1) + binder
        truncated = serialized[0...(serialized.bytesize - binders_size)]

        binder = compute_psk_binder(psk_entry[:psk], truncated, hash_alg)
        psk_ext.binders = [binder]
      end

      # Build a Handshake{Finished} message bound to the current key schedule
      # and transcript. Returns nil if the schedule is not yet ready (no
      # client_handshake_traffic_secret or no server_hello to pick the hash).
      def build_client_finished_handshake
        return nil unless @key_schedule && @server_hello
        return nil unless @key_schedule.client_handshake_traffic_secret

        verify_data = @key_schedule.finished_verify_data(@transcript_hash.hash, from: :client)

        Handshake.new.tap do |hs|
          hs.handshake_type = Handshake::HANDSHAKE_TYPE[:finished]
          hs.message = Handshake::Finished.new.tap { |fin| fin.verify_data = verify_data }
        end
      end

      def respond_to_finished
        records = [] #: Array[String]

        # RFC 8446 §4.5: EndOfEarlyData is only sent when the server
        # accepted 0-RTT (signalled by echoing EarlyData in EE). If the
        # server rejected PSK or 0-RTT, the client must not transmit
        # EOED — anything we already sent at 0-RTT is replayed at 1-RTT.
        if @early_data_available && @early_cipher && early_data_accepted?
          eoed = send_end_of_early_data
          records << eoed if eoed
        else
          # Drop early-data state so application-level retransmits go
          # through the 1-RTT cipher (handled by callers).
          @early_data_available = false
          @early_cipher = nil
        end

        if @client_auth_required
          records.concat(send_client_certificate)
        end

        finished = Handshake::Finished.new.tap do |fin|
          fin.verify_data = @key_schedule.finished_verify_data(@transcript_hash.hash, from: :client)
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
        records << ciphertext.serialize
      end

      private def send_client_certificate
        cert_msg = Handshake::Certificate.new
        cert_msg.certificate_request_context = @certificate_request&.certificate_request_context || ""

        if @config.client_certificate
          cert_msg.certificate_entries << Handshake::Certificate::CertificateEntry.new(
            opaque_certificate_data: @config.client_certificate.to_der,
            extensions: []
          )
        end
        # If no client certificate is configured, send empty Certificate

        hs = Handshake.new
        hs.handshake_type = Handshake::HANDSHAKE_TYPE[:certificate]
        hs.message = cert_msg

        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = hs.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        ciphertext = @client_cipher.encrypt(plaintext: innerplaintext, phase: :handshake)
        [ciphertext.serialize]
      end

      def finished?
        @state == State::CONNECTED
      end

      # Peer hooks
      def negotiated_cipher_suite
        @server_hello&.cipher_suite
      end

      def own_cipher
        @client_cipher
      end

      def peer_cipher
        @server_cipher
      end

      private def rebuild_client_hello_for_retry(hrr, requested_group:)
        # Generate new key pair for the requested group if needed
        if requested_group && !@pkeys.any? { |pk| pk[:group] == requested_group }
          @pkeys << { group: requested_group, pkey: generate_pkey(requested_group) }
        end

        retry_pkeys = if requested_group
          @pkeys.select { |pk| pk[:group] == requested_group }
        else
          @pkeys
        end

        hs_clienthello = Raiha::TLS::Handshake.new.tap do |hs|
          hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:client_hello]
          hs.message = Raiha::TLS::Handshake::ClientHello.build.tap do |ch|
            ch.server_name = @server_name if @server_name

            # Update supported_groups to include requested group
            sg_ext = ch.extensions.find { |e| e.is_a?(Handshake::Extension::SupportedGroups) }
            if sg_ext && requested_group && !sg_ext.groups.include?(requested_group)
              sg_ext.groups.unshift(requested_group)
            end

            # Add Cookie extension if present in HRR
            cookie_ext = hrr.extensions.find { |e| e.is_a?(Handshake::Extension::Cookie) }
            if cookie_ext
              ch.extensions << cookie_ext
            end
          end
        end
        hs_clienthello.message.setup_key_share(retry_pkeys)
        @client_hello = hs_clienthello.message
        @transcript_hash[:client_hello_retry] = hs_clienthello.serialize
        @retry_client_hello_record = Record::TLSPlaintext.serialize(hs_clienthello)
      end

      private def transition_state(state)
        if @state == State::START && state == State::WAIT_SH
          @state = state
        elsif @state == State::WAIT_SH && state == State::WAIT_SH_RETRY
          @state = state
        elsif @state == State::WAIT_SH_RETRY && state == State::WAIT_SH
          @state = state
        elsif @state == State::WAIT_SH && state == State::WAIT_EE
          @state = state
        elsif @state == State::WAIT_EE && state == State::WAIT_CERT_CR
          @state = state
        elsif @state == State::WAIT_EE && state == State::WAIT_FINISHED
          # RFC 8446 §A.1 / §2.2: PSK resumption skips Certificate and
          # CertificateVerify, so EncryptedExtensions hands directly off
          # to waiting for the server Finished.
          @state = state
        elsif @state == State::WAIT_CERT_CR && state == State::WAIT_CERT
          @state = state
        elsif @state == State::WAIT_CERT && state == State::WAIT_CV
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
          raise Raiha::TLS::Error, "TODO: #{@state} -> #{state} is wrong state transition"
        end
      end

      private def valid_server_hello?
        return false unless @server_hello.legacy_session_id_echo == @client_hello.legacy_session_id
        return false unless @client_hello.cipher_suites.map(&:name).include?(@server_hello.cipher_suite.name)

        return false unless @server_hello.extensions.any? { |ext|
          ext.is_a?(Raiha::TLS::Handshake::Extension::SupportedVersions) && ext.extension_data == "\x03\x04"
        }
        # RFC 8446 §4.1.3: ServerHello must offer a key_share (full
        # handshake or PSK-DHE-KE) or a PreSharedKey (PSK-only, not yet
        # supported here but accepted to detect resumption).
        has_key_share = @server_hello.extensions.any? { |ext| ext.is_a?(Raiha::TLS::Handshake::Extension::KeyShare) }
        has_pre_shared_key = @server_hello.extensions.any? { |ext| ext.is_a?(Raiha::TLS::Handshake::Extension::PreSharedKey) }
        return false unless has_key_share || has_pre_shared_key

        true
      end

      private def generate_pkey(group)
        case group
        when "x25519"
          OpenSSL::PKey.generate_key("x25519")
        when "x448"
          OpenSSL::PKey.generate_key("x448")
        else
          OpenSSL::PKey::EC.generate(group)
        end
      end

      private def setup_key_schedule
        server_key_share = @server_hello.key_share
        @key_schedule.cipher_suite = @server_hello.cipher_suite
        @key_schedule.group = server_key_share.groups.first[:group]
        @key_schedule.public_key = server_key_share.groups.first[:key_exchange]
        @key_schedule.pkey = @pkeys.find { |pkeys| pkeys[:group] == server_key_share.groups.first[:group] }[:pkey]
        @key_schedule.compute_shared_secret
        if psk_mode?
          # RFC 8446 §7.1: the Early Secret must be derived from the
          # ticket's PSK so that the salt fed into the Handshake Secret
          # below matches the server's key schedule. setup_early_data_cipher
          # may have already set this when 0-RTT was offered, but resumption
          # without 0-RTT also needs it.
          psk_entry = @session_ticket_store.get(@server_name || "")
          @key_schedule.psk = psk_entry[:psk] if psk_entry
        else
          # The server rejected our PSK (or we never offered one). Even if
          # we set the PSK earlier for 0-RTT, the handshake secret derives
          # from a zero IKM in full-handshake mode (RFC 8446 §7.1).
          @key_schedule.psk = nil
        end
        @key_schedule.derive_secret(secret: :early_secret, label: "derived", transcript_hash: @transcript_hash.empty_digest)
        @key_schedule.derive_client_handshake_traffic_secret(@transcript_hash.hash)
        @key_schedule.derive_server_handshake_traffic_secret(@transcript_hash.hash)
      end

      private def psk_mode?
        return false unless @server_hello
        @server_hello.extensions.any? { |ext| ext.is_a?(Handshake::Extension::PreSharedKey) }
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
        raise unless finished.message.verify_data == @key_schedule.finished_verify_data(@transcript_hash.hash, from: :server)
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
        path = ENV["SSLKEYLOGFILE"]
        return unless path && !path.empty?

        body = <<~SSLKEYLOGFILE
          SERVER_HANDSHAKE_TRAFFIC_SECRET #{@client_hello.random.unpack1("H*")} #{@key_schedule.server_handshake_traffic_secret.unpack1("H*")}
          SERVER_TRAFFIC_SECRET_0 #{@client_hello.random.unpack1("H*")} #{@key_schedule.server_application_traffic_secret[0].unpack1("H*")}
          CLIENT_HANDSHAKE_TRAFFIC_SECRET #{@client_hello.random.unpack1("H*")} #{@key_schedule.client_handshake_traffic_secret.unpack1("H*")}
          CLIENT_TRAFFIC_SECRET_0 #{@client_hello.random.unpack1("H*")} #{@key_schedule.client_application_traffic_secret[0].unpack1("H*")}
        SSLKEYLOGFILE

        File.open(path, "a") do |f|
          f.write(body)
        end
      end
    end
  end
end
