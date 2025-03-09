# frozen_string_literal: true

require_relative "context"
require_relative "record"
require_relative "handshake"
require_relative "key_schedule"
require_relative "aead"
require_relative "transcript_hash"
require_relative "../crypto_util"

module Raiha
  module TLS
    class Server < Context
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
      end

      attr_reader :state

      def initialize
        @state = State::START
        @cipher_suite = nil
        @client_hello = nil
        @server_hello = nil
        @buffer = []
        @received = []
        @extensions = {}
        @key_schedule = KeySchedule.new(mode: :server)
        @transcript_hash = TranscriptHash.new
        @server_certificate = OpenSSL::X509::Certificate.load_file(File.expand_path("../../../tmp/server.crt", __dir__)).first # TODO
        @server_private_key = OpenSSL::PKey::RSA.new(File.read(File.expand_path("../../../tmp/server.key", __dir__))) # TODO
      end

      def receive(datagram)
        @received = Record.deserialize(datagram)

        case @state
        when State::START
          receive_client_hello
          select_parameters
        when State::NEGOTIATED
          receive_finished
        end
      end

      def datagrams_to_send
        case @state
        when State::RECVD_CH
          [
            build_server_hello,
            build_encrypted_extensions,
            build_certificate,
            build_certificate_verify,
            build_finished,
          ].flatten
        else
          # TODO: WIP
        end
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
        transition_state(State::RECVD_CH)
      end

      def choose_cipher_suite
        @cipher_suite = @client_hello.cipher_suites.find(&:supported?)
        @transcript_hash.digest_algorithm = @cipher_suite.hash_algorithm
      end

      def choose_group
        supported_groups = @extensions[:client_hello].find { |ext| ext.is_a?(Handshake::Extension::SupportedGroups) }
        raise unless supported_groups

        if supported_groups.groups.include?("x25519") # TODO: select supported group correctly
          @pkey = { group: "x25519", pkey: OpenSSL::PKey.generate_key("x25519") }
        end
      end

      def select_parameters
        raise unless @client_hello
        # TODO: select parameters

        unless choose_cipher_suite
          raise "TODO: alert? cannot choose cipher suite"
        end

        choose_group
      end

      def build_server_hello
        handshake = Handshake.new.tap do |hs|
          hs.handshake_type = Handshake::HANDSHAKE_TYPE[:server_hello]
          hs.message = Handshake::ServerHello.build_from_client_hello(@client_hello).tap do |sh|
            sh.extensions += [
              Handshake::Extension::KeyShare.new(on: :server_hello).tap do |ks|
                # TODO: ugly
                if @pkey[:group] == "x25519"
                  ks.groups = [{ group: @pkey[:group], key_exchange: @pkey[:pkey].raw_public_key }] # TODO: x25519 (OpenSSL::PKey::PKey) only
                elsif @pkey[:group] == "prime256v1"
                  ks.groups = [{ group: @pkey[:group], key_exchange: @pkey[:pkey].public_key.to_octet_string(:uncompressed) }]
                else
                  raise "TODO: #{@pkey[:group]}"
                end
              end
            ]
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
            cert.opaque_certificate_data = @server_certificate.to_der
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

          next if received.plaintext? && received.change_cipher_spec?
          inner_plaintext = @client_cipher.decrypt(ciphertext: received, phase: :handshake)
          finished = Handshake.deserialize_multiple(inner_plaintext.content).find { |hs| hs.message.is_a?(Handshake::Finished) }

          if finished
            verify_finished(finished)
            transition_state(State::CONNECTED)
            @server_cipher.reset_sequence_number
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

      private def transition_state(state)
        if @state == State::START && state == State::RECVD_CH
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
        @key_schedule.derive_secret(secret: :early_secret, label: "derived", transcript_hash: @transcript_hash.hash)
        @key_schedule.derive_client_handshake_traffic_secret(@transcript_hash.hash)
        @key_schedule.derive_server_handshake_traffic_secret(@transcript_hash.hash)
      end

      private def setup_cipher
        @server_cipher = AEAD.new(cipher_suite: @cipher_suite, key_schedule: @key_schedule, mode: :server)
        @client_cipher = AEAD.new(cipher_suite: @cipher_suite, key_schedule: @key_schedule, mode: :client)
      end

      private def finished_verify_data(key)
        # TODO: don't hardcode hash algorithm
        finished_key = CryptoUtil.hkdf_expand_label(key, "finished", "", OpenSSL::Digest.new("sha256").digest_length)
        OpenSSL::HMAC.digest("sha256", finished_key, @transcript_hash.hash)
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
