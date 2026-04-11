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
        respond_to_finished
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
        @client_hello = hs_clienthello.message
        @transcript_hash.digest_algorithm = @client_hello.cipher_suites.first.hash_algorithm

        psk_entry = @session_ticket_store.get(@server_name || "")
        if psk_entry
          add_psk_to_client_hello(hs_clienthello, psk_entry)
          @early_data_available = true
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

        innerplaintext = Record::TLSInnerPlaintext.new.tap do |inner|
          inner.content = handshake.serialize
          inner.content_type = Record::CONTENT_TYPE[:handshake]
        end
        ciphertext = @early_cipher.encrypt(plaintext: innerplaintext, phase: :early)
        ciphertext.serialize
      end

      private def setup_early_data_cipher(psk_entry)
        cipher_suite = @client_hello.cipher_suites.first
        hash_alg = cipher_suite.hash_algorithm
        digest_length = OpenSSL::Digest.new(hash_alg).digest_length

        # Set cipher suite on key_schedule so hash_algorithm is available
        @key_schedule.cipher_suite = cipher_suite

        # Derive early_secret from PSK
        early_secret = OpenSSL::HMAC.digest(hash_alg, "\x00" * digest_length, psk_entry[:psk])
        @key_schedule.instance_variable_set(:@ikm, { early_secret: early_secret, handshake_secret: nil, main_secret: nil })

        # Derive client_early_traffic_secret
        @key_schedule.derive_client_early_traffic_secret(@transcript_hash.hash)

        # Create early data cipher
        @early_cipher = AEAD.new(cipher_suite: cipher_suite, key_schedule: @key_schedule, mode: :client)
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

      private def compute_psk_binder(psk, truncated_client_hello, hash_alg)
        digest_length = OpenSSL::Digest.new(hash_alg).digest_length

        # early_secret = HKDF-Extract(0, PSK)
        early_secret = OpenSSL::HMAC.digest(hash_alg, "\x00" * digest_length, psk)

        # binder_key = Derive-Secret(early_secret, "res binder", "")
        empty_hash = OpenSSL::Digest.new(hash_alg).digest
        binder_key = CryptoUtil.hkdf_expand_label(early_secret, "res binder", empty_hash, digest_length, hash: hash_alg)

        # finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
        finished_key = CryptoUtil.hkdf_expand_label(binder_key, "finished", "", digest_length, hash: hash_alg)

        # binder = HMAC(finished_key, Transcript-Hash(truncated_client_hello))
        transcript_hash = OpenSSL::Digest.new(hash_alg).digest(truncated_client_hello)
        OpenSSL::HMAC.digest(hash_alg, finished_key, transcript_hash)
      end

      def respond_to_finished
        records = []

        if @client_auth_required
          records.concat(send_client_certificate)
        end

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
        hash_alg = @server_hello.cipher_suite.hash_algorithm
        finished_key = CryptoUtil.hkdf_expand_label(key, "finished", "", OpenSSL::Digest.new(hash_alg).digest_length, hash: hash_alg)
        OpenSSL::HMAC.digest(hash_alg, finished_key, @transcript_hash.hash)
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
