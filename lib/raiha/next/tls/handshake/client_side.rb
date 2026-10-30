# frozen_string_literal: true

require_relative "../cipher_suite"
require_relative "../config"
require_relative "../event"
require_relative "../extension"
require_relative "../iana"
require_relative "../key_schedule"
require_relative "../session"
require_relative "../verifier"
require_relative "authentication_messages"
require_relative "client_hello_builder"
require_relative "key_update_handling"

module Raiha::Next::TLS
  module Handshake
    # The client's states, table of expected messages and handlers, and what
    # it keeps for one connection. The checks in each handler follow the
    # state machine's table for that state, in its order; the first failure
    # is the one reported.
    class ClientSide
      include KeyUpdateHandling

      STATES = %i[wait_sh wait_sh2 wait_ee wait_cert_cr wait_cert wait_cv wait_finished connected failed].freeze

      # State => epoch => the message types acceptable there. KeyUpdate in
      # :connected only where the Profile allows it.
      EXPECTED = {
        wait_sh: { initial: Set[ServerHello::MSG_TYPE] },
        wait_sh2: { initial: Set[ServerHello::MSG_TYPE] },
        wait_ee: { handshake: Set[EncryptedExtensions::MSG_TYPE] },
        wait_cert_cr: { handshake: Set[Certificate::MSG_TYPE, CertificateRequest::MSG_TYPE] },
        wait_cert: { handshake: Set[Certificate::MSG_TYPE] },
        wait_cv: { handshake: Set[CertificateVerify::MSG_TYPE] },
        wait_finished: { handshake: Set[Finished::MSG_TYPE] },
        connected: { application: Set[NewSessionTicket::MSG_TYPE, KeyUpdate::MSG_TYPE] },
        failed: {} # steep:ignore
      }.freeze #: Hash[Symbol, Hash[epoch, Set[Integer]]]

      NONE = Set.new.freeze #: Set[Integer]

      # RFC 9001 "Enabling 0-RTT": a QUIC server sends this, and only this, as
      # max_early_data_size.
      EARLY_DATA_SENTINEL = 0xffffffff

      attr_reader :cipher_suite, :group, :alpn, :peer_certificates, :exporter_values, :peer_record_size_limit

      def initialize(conductor, server_name:, sni:, extensions:, tracer:, session:)
        @conductor = conductor
        @config = conductor.config
        @keyring = conductor.keyring
        @server_name = server_name
        @sni = sni
        @extensions = extensions
        @authentication = AuthenticationMessages.new(AuthenticationMessages::Parameters::CLIENT, tracer:)
        # The session given to resume, until it is not offered, and the PSK
        # offered with it.
        @session = session
        @psk = nil #: String?
        @client_hello = nil #: ClientHello?
        @hello_retry_request = nil #: ServerHello?
        # @type var key_pairs: Array[KeyExchange::KeyPair]
        key_pairs = []
        @key_pairs = key_pairs
        @cipher_suite = nil #: CipherSuite?
        @group = nil #: Symbol?
        @alpn = nil #: String?
        @peer_record_size_limit = nil #: Integer?
        @certificate_request = nil #: CertificateRequest?
        # @type var peer_certificates: Array[OpenSSL::X509::Certificate]
        peer_certificates = []
        @peer_certificates = peer_certificates
        # When the full handshake whose key material the connection holds
        # took place (milliseconds), nil until the handshake is over.
        @authenticated_at = nil #: Integer?
        # @type var exporter_values: Hash[String, String]
        exporter_values = {}
        @exporter_values = exporter_values
        start_key_updates
      end

      # Sends the ClientHello, with the session's PSK when it passes the
      # checks.
      def start(now:)
        session = session_to_offer(now)
        built = ClientHelloBuilder.build(config: @config, keyring: @keyring, server_name: @sni, extensions: @extensions)
        @key_pairs = built.key_pairs
        @client_hello = session ? offer(built.client_hello, session, now) : @conductor.emit_message!(:initial, built.client_hello)
        @conductor.transition!(:wait_sh)
      end

      def expected_types(state, epoch)
        return NONE if state.nil?
        types = EXPECTED.fetch(state).fetch(epoch, NONE)
        @config.profile.allow_key_update_message ? types : types - [KeyUpdate::MSG_TYPE]
      end

      # A CertificateRequest after the handshake: v1 has no post-handshake
      # authentication and never offers it. QUIC maps this reason to
      # PROTOCOL_VIOLATION (RFC 9001 "Peer Authentication").
      def unexpected_reason(state, msg_type)
        if state == :connected && msg_type == CertificateRequest::MSG_TYPE
          :post_handshake_certificate_request
        else
          :unexpected_message
        end
      end

      def handle(message, raw:, transcript_hash_before:, now:)
        case message
        when ServerHello then server_hello(message, raw)
        when EncryptedExtensions then encrypted_extensions(message)
        when CertificateRequest then certificate_request(message)
        when Certificate then certificate(message, now)
        when CertificateVerify then certificate_verify(message, transcript_hash_before) # steep:ignore
        when Finished then finished(message, transcript_hash_before, now) # steep:ignore
        when NewSessionTicket then new_session_ticket(message, now)
        when KeyUpdate then receive_key_update(message)
        end
      end

      def forget_secrets!
        @psk&.clear
        @key_pairs = []
        @exporter_values.each_value(&:clear).clear
        nil
      end

      private def client_hello = @client_hello || raise("no ClientHello was sent")

      private def key_schedule = @conductor.key_schedule || raise("the key schedule has not started")

      private def suite = @cipher_suite || raise("no cipher suite was negotiated")

      private def own_side = :client

      private def peer_side = :server

      private def fail!(alert, reason) = @conductor.fail!(alert, reason)

      private def offered_types = client_hello.extensions.map(&:extension_type)

      private def server_hello(message, raw)
        hrr = @hello_retry_request
        # 0a to 0c, after a HelloRetryRequest, before everything else.
        if hrr
          failure = check_after_hello_retry_request(message, hrr)
          return fail!(failure.alert, failure.reason) if failure
        end
        # 1
        suite = CipherSuite.find(message.cipher_suite)
        unless suite && client_hello.cipher_suites.include?(suite.id) && @config.cipher_suite_ids.include?(suite.id)
          return fail!(:illegal_parameter, :cipher_suite_not_offered)
        end
        # 2
        unless message.legacy_session_id_echo == client_hello.legacy_session_id
          return fail!(:illegal_parameter, :legacy_session_id_echo)
        end
        # 3: the HelloRetryRequest may bring a cookie we did not send.
        allowed = offered_types
        allowed += [Extension::Cookie::TYPE] if message.hello_retry_request?
        unless message.extensions.all? { |ext| allowed.include?(ext.extension_type) }
          return fail!(:unsupported_extension, :unsolicited_extension)
        end
        message.hello_retry_request? ? hello_retry_request(message, raw, suite) : accept_server_hello(message, raw, suite)
      end

      # RFC 9846 "Hello Retry Request" and "Key Share": one
      # HelloRetryRequest, then the same suite and the group it asked for.
      private def check_after_hello_retry_request(message, hrr)
        # 0a
        return Violation.new(alert: :unexpected_message, reason: :second_hello_retry_request) if message.hello_retry_request?
        # 0b
        return Violation.new(alert: :illegal_parameter, reason: :cipher_suite_changed) unless message.cipher_suite == hrr.cipher_suite
        # 0c
        share = message.extension(Extension::KeyShare::TYPE)
        requested = hrr.extension(Extension::KeyShare::TYPE)
        case requested
        when Extension::KeyShare::HRR
          case share
          when Extension::KeyShare::SH
            return Violation.new(alert: :illegal_parameter, reason: :key_share_group_changed) unless share.server_share.group == requested.selected_group
          end
        end
        nil
      end

      private def hello_retry_request(hrr, raw, suite)
        # 4: the server cannot send anything before our second ClientHello.
        return fail!(:unexpected_message, :data_after_hello_retry_request) if @conductor.pending_input?
        requested = case (ext = hrr.extension(Extension::KeyShare::TYPE))
          when Extension::KeyShare::HRR then ext.selected_group
          end
        if requested
          # 5
          offered_groups = @config.group_ids
          shared_groups = key_share_groups(client_hello)
          if !offered_groups.include?(requested) || shared_groups.include?(requested)
            return fail!(:illegal_parameter, :hello_retry_request_group)
          end
        elsif hrr.extensions.none? { |ext| ext.extension_type == Extension::Cookie::TYPE }
          # 6: nothing would change in the second ClientHello.
          return fail!(:illegal_parameter, :hello_retry_request_changes_nothing)
        end
        @conductor.receive_hello_retry_request!(raw, suite.hash_algorithm)
        @hello_retry_request = hrr
        second = ClientHelloBuilder.retry(client_hello, hrr) do |group|
          key_pair = @keyring.key_exchange.generate(IANA::NAMED_GROUPS.fetch(group))
          @key_pairs = [key_pair]
          Extension::KeyShare::Entry.new(group:, key_exchange: key_pair.public_bytes)
        end
        @client_hello = @conductor.emit_message!(:initial, second)
        @conductor.transition!(:wait_sh2)
      end

      private def accept_server_hello(message, raw, suite)
        share = case (ext = message.extension(Extension::KeyShare::TYPE))
          when Extension::KeyShare::SH then ext.server_share
          end
        # 7: without a PSK there is no key exchange but this one.
        return fail!(:illegal_parameter, :missing_key_share) unless share
        # 8
        key_pair = @key_pairs.find { |pair| Config::GROUPS_BY_NAME[pair.group] == share.group }
        return fail!(:illegal_parameter, :key_share_group_not_offered) unless key_pair
        # 10
        shared_secret = @keyring.key_exchange.decapsulate(key_pair, share.key_exchange)
        return fail!(:illegal_parameter, :invalid_key_share) unless shared_secret

        @conductor.record_server_hello!(raw, suite.hash_algorithm)
        @cipher_suite = suite
        @group = key_pair.group
        @key_pairs = []
        schedule = @conductor.start_key_schedule(hash: suite.hash_algorithm, client_random: client_hello.random)
        schedule.handshake!(shared_secret)
        shared_secret.clear
        transcript_hash = @conductor.transcript_hash
        client_secret = schedule.client_handshake_traffic_secret(transcript_hash)
        server_secret = schedule.server_handshake_traffic_secret(transcript_hash)
        moved = @conductor.change_epochs!(cipher_suite: suite, read: :handshake, write: :handshake,
          secrets: [[:handshake, :read, server_secret], [:handshake, :write, client_secret]])
        @conductor.transition!(:wait_ee) if moved
      end

      private def encrypted_extensions(message)
        types = message.extensions.map(&:extension_type)
        profile = @config.profile
        # The other direction of RFC 9001's rule on quic_transport_parameters.
        unless (types & profile.forbidden_extensions).empty?
          return fail!(:unsupported_extension, :forbidden_extension)
        end
        # 1
        return fail!(:unsupported_extension, :unsolicited_extension) unless (types - offered_types).empty?
        # 4
        alpn = case (ext = message.extension(Extension::Alpn::TYPE))
          when Extension::Alpn then ext.protocol_name_list
          end
        if alpn && !(alpn.size == 1 && @config.alpn.include?(alpn.fetch(0)))
          return fail!(:no_application_protocol, :alpn_not_offered)
        end
        # 5
        if profile.require_alpn && !@config.alpn.empty? && alpn.nil?
          return fail!(:no_application_protocol, :alpn_not_selected)
        end
        # 6
        missing = profile.required_extensions - types
        return fail!(:missing_extension, :required_extension) unless missing.empty?

        @alpn = alpn&.first
        case (ext = message.extension(Extension::RecordSizeLimit::TYPE))
        when Extension::RecordSizeLimit then @peer_record_size_limit = ext.record_size_limit
        end
        message.extensions.each do |ext|
          next if Config::RESERVED_EXTENSIONS.include?(ext.extension_type)
          @conductor.event!(Event::PeerExtension.new(type: ext.extension_type, data: ext.encode, message: EncryptedExtensions::MSG_TYPE))
        end
        @conductor.transition!(:wait_cert_cr)
      end

      private def certificate_request(message)
        # Empty during the handshake (RFC 9846 "Certificate Request").
        return fail!(:decode_error, :certificate_request_context) unless message.certificate_request_context.empty?
        @certificate_request = message
        @conductor.transition!(:wait_cert)
      end

      private def certificate(message, now)
        return fail!(:decode_error, :certificate_request_context) unless message.certificate_request_context.empty?
        # RFC 9846 "Certificate": a server must send a certificate.
        return fail!(:decode_error, :empty_certificate) if message.certificate_list.empty?
        # We request neither OCSP stapling nor SCTs.
        return fail!(:unsupported_extension, :unsolicited_extension) if message.certificate_list.any? { |entry| !entry.extensions.empty? }
        result = @authentication.verify_certificate(message, keyring: @keyring, server_name: @server_name, now:,
          max_chain_length: @config.max_certificate_chain_length, context: "".b)
        case result
        when AuthenticationMessages::Failure then fail!(result.alert, result.reason)
        else
          @peer_certificates = result
          @conductor.transition!(:wait_cv)
        end
      end

      private def certificate_verify(message, transcript_hash)
        leaf = @peer_certificates.first or raise "no peer certificate to verify against"
        result = @authentication.verify_certificate_verify(message, leaf, offered: @config.signature_algorithm_ids,
          transcript_hash:)
        case result
        when AuthenticationMessages::Failure then fail!(result.alert, result.reason)
        else @conductor.transition!(:wait_finished)
        end
      end

      private def finished(message, transcript_hash, now)
        schedule = key_schedule
        case (result = @authentication.verify_finished(message, schedule, transcript_hash))
        when AuthenticationMessages::Failure then return fail!(result.alert, result.reason)
        end

        schedule.main!
        through_server_finished = @conductor.transcript_hash
        server_secret = schedule.server_application_traffic_secret(through_server_finished)
        client_secret = schedule.client_application_traffic_secret(through_server_finished)
        @exporter_values = schedule.exporter_values(@config.exporter_labels, through_server_finished)
        return unless @conductor.change_epochs!(cipher_suite: suite, read: :application,
          secrets: [[:application, :read, server_secret], [:application, :write, client_secret]])
        send_client_flight(schedule)
        schedule.resumption!(@conductor.transcript_hash)
        @authenticated_at = (now.to_r * 1000).floor
        @conductor.change_epochs!(cipher_suite: suite, write: :application)
        @conductor.transition!(:connected)
        @conductor.event!(Event::HandshakeComplete.new(
          server_name: @server_name, alpn: @alpn, cipher_suite: suite.name, group: @group, resumed: false,
          early_data_accepted: false, peer_certificates: @peer_certificates, peer_verified: @keyring.peer_verified?
        ))
      end

      # Our Certificate and CertificateVerify when the server asked, then our
      # Finished. With no identity that fits the request, an empty
      # Certificate and no CertificateVerify (RFC 9846 "Certificate").
      private def send_client_flight(schedule)
        if (request = @certificate_request)
          # @type var algorithms: Array[Integer]
          algorithms = case (ext = request.extension(Extension::SignatureAlgorithms::TYPE))
            when Extension::SignatureAlgorithms then ext.supported_signature_algorithms
            else []
            end
          authorities = case (ext = request.extension(Extension::CertificateAuthorities::TYPE))
            when Extension::CertificateAuthorities then ext.authorities
            end
          credential, scheme = @keyring.client_credential(signature_algorithms: algorithms, certificate_authorities: authorities)
          @conductor.emit_message!(:handshake, @authentication.certificate(credential, context: request.certificate_request_context))
          if credential && scheme
            @conductor.emit_message!(:handshake, @authentication.certificate_verify(credential, scheme, @conductor.transcript_hash))
          end
        end
        @conductor.emit_message!(:handshake, @authentication.finished(schedule, @conductor.transcript_hash))
      end

      # A ticket becomes a Session the application may keep, its age counted
      # from now. With QUIC, max_early_data_size is checked first, a ticket
      # ignored or not (RFC 9001 "Enabling 0-RTT"); a client that does not
      # resume ignores it then (RFC 9846 "New Session Ticket Message").
      private def new_session_ticket(message, now)
        early_data = case (ext = message.extension(Extension::EarlyData::TYPE))
          when Extension::EarlyData::NST then ext.max_early_data_size
          end
        if @config.profile.max_early_data_size_policy == :sentinel && early_data && early_data != EARLY_DATA_SENTINEL
          return fail!(:illegal_parameter, :max_early_data_size_not_sentinel)
        end
        return unless @config.resumption
        @conductor.event!(Event::NewSessionTicket.new(session: Session.new(
          ticket: message.ticket, ticket_nonce: message.ticket_nonce, resumption_secret: key_schedule.resumption_secret,
          cipher_suite: suite.id, issued_at: (now.to_r * 1000).floor, lifetime: message.ticket_lifetime,
          age_add: message.ticket_age_add, max_early_data_size: early_data || 0, server_name: @server_name, alpn: @alpn,
          peer_certificates: @peer_certificates.map(&:to_der), authenticated_at: @authenticated_at || raise("no handshake to resume"),
          peer_verified: @keyring.peer_verified?
        )))
      end


      # The session to offer, or nil, with Event::SessionNotOffered, for one
      # that fails a check.
      private def session_to_offer(now)
        session = @session or return nil
        reason = session_refusal(session, now) or return session
        @session = nil
        @conductor.event!(Event::SessionNotOffered.new(reason:))
        nil
      end

      # The first check, in order, that `session` fails at `now`: those after
      # which no connection can use it come first. The chain is verified as
      # for the name it was verified for, so that another name now is
      # :server_name_mismatch; a name that is the same was valid for the
      # leaf then and still is (RFC 9846 "New Session Ticket Message").
      private def session_refusal(session, now)
        return :ticket_expired unless session.usable?(now:)
        chain = session.peer_certificates.map { |der| Crypto::Certificate.parse(der) }
        return :untrusted_chain if chain.empty? || chain.include?(nil)
        # @type var parsed: Array[OpenSSL::X509::Certificate]
        parsed = chain.compact
        # A certificate always has its dates; OpenSSL's signature allows nil.
        return :certificate_expired if parsed.any? { |cert| cert.not_before > now || cert.not_after < now } # steep:ignore
        return :unverified_origin unless session.peer_verified
        result = @keyring.verifier.verify(chain: parsed, server_name: session.server_name, now:, purpose: :server)
        raise UsageError, "a Verifier must return a Verifier::Result, not #{result.class}" unless result.is_a?(Verifier::Result)
        return :untrusted_chain unless result.ok
        return :server_name_mismatch unless session.server_name == @server_name
        hash = CipherSuite.find(session.cipher_suite)&.hash_algorithm
        offered = @config.cipher_suite_ids.any? { |id| CipherSuite.find(id)&.hash_algorithm == hash }
        return :cipher_suite_unavailable unless hash && offered
        nil
      end

      # `client_hello` with the session's PSK (RFC 9846 "Pre-Shared Key
      # Extension"): one identity, its age as the client counts it, and
      # pre_shared_key last; psk_dhe_ke is offered already.
      private def offer(client_hello, session, now)
        suite = CipherSuite.find(session.cipher_suite) or raise "the session's cipher suite was checked"
        identity = Extension::PreSharedKey::Identity.new(identity: session.ticket, obfuscated_ticket_age: session.obfuscated_ticket_age(now))
        placeholder = Extension::PreSharedKey::CH.new(identities: [identity], binders: ["\x00".b * suite.hash_length])
        psk = @psk = session.psk
        @conductor.emit_client_hello_with_binders!(client_hello.with(extensions: client_hello.extensions + [placeholder]), suite.hash_algorithm) do |transcript_hash|
          schedule = KeySchedule.new(hash: suite.hash_algorithm, psk:)
          [schedule.binder(kind: :resumption, transcript_hash:)].tap { schedule.discard! }
        end
      end

      private def key_share_groups(client_hello)
        # @type var none: Array[Integer]
        none = []
        case (ext = client_hello.extension(Extension::KeyShare::TYPE))
        when Extension::KeyShare::CH then ext.client_shares.map(&:group)
        else none
        end
      end
    end
  end
end
