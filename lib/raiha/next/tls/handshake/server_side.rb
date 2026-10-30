# frozen_string_literal: true

require_relative "../cipher_suite"
require_relative "../config"
require_relative "../event"
require_relative "../extension"
require_relative "../iana"
require_relative "../key_schedule"
require_relative "../server_name"
require_relative "../ticket"
require_relative "../trace"
require_relative "authentication_messages"
require_relative "key_update_handling"

module Raiha::Next::TLS
  module Handshake
    # The server's states, table of expected messages and handlers, and what
    # it keeps for one connection.
    #
    # From the ClientHello to the first flight there is nothing to wait for
    # (the Verifier and everything else is synchronous), so receiving a
    # ClientHello runs straight through: the checks in the state machine's
    # table, the choice of suite, group and ALPN, a HelloRetryRequest if the
    # client sent no key share for the group, then the certificate and the
    # first flight. A second ClientHello takes the same path, after the
    # checks that it differs from the first only as RFC 9846 allows.
    class ServerSide
      include KeyUpdateHandling

      STATES = %i[wait_ch2 wait_eoed wait_cert wait_cv wait_finished connected failed].freeze

      EXPECTED = {
        wait_ch2: { initial: Set[ClientHello::MSG_TYPE] },
        wait_eoed: { early_data: Set[EndOfEarlyData::MSG_TYPE] },
        wait_cert: { handshake: Set[Certificate::MSG_TYPE] },
        wait_cv: { handshake: Set[CertificateVerify::MSG_TYPE] },
        wait_finished: { handshake: Set[Finished::MSG_TYPE] },
        connected: { application: Set[KeyUpdate::MSG_TYPE] },
        failed: {} # steep:ignore
      }.freeze #: Hash[Symbol, Hash[epoch, Set[Integer]]]

      NONE = Set.new.freeze #: Set[Integer]

      # What RFC 9846 "Client Hello" lets the second ClientHello change.
      ALLOWED_TO_CHANGE = [
        Extension::KeyShare::TYPE, Extension::EarlyData::TYPE, Extension::PreSharedKey::TYPE,
        Extension::Cookie::TYPE, ClientHelloBuilder::PADDING
      ].freeze

      PSK_DHE_KE = 1

      # The ticket a server resumes with, and the index of its identity in
      # the ClientHello.
      class Resumption < Data.define(:index, :ticket); end

      attr_reader :cipher_suite, :group, :alpn, :peer_certificates, :exporter_values, :peer_record_size_limit

      def initialize(conductor, extensions:, tracer:, resumption_binding:, early_data_context:)
        @conductor = conductor
        @config = conductor.config
        @keyring = conductor.keyring
        @extensions = extensions
        @tracer = tracer
        @resumption_binding = resumption_binding
        @early_data_context = early_data_context
        # When the full handshake whose key material the connection holds
        # took place (milliseconds), nil until the handshake is over; a
        # resumption takes it from the ticket.
        @authenticated_at = nil #: Integer?
        @resumption = nil #: Resumption?
        @authentication = AuthenticationMessages.new(AuthenticationMessages::Parameters::SERVER, tracer:)
        @client_hello = nil #: ClientHello?
        @hello_retry_request = nil #: ServerHello?
        @server_name = nil #: String?
        @cipher_suite = nil #: CipherSuite?
        @group = nil #: Symbol?
        @alpn = nil #: String?
        @peer_record_size_limit = nil #: Integer?
        # @type var peer_certificates: Array[OpenSSL::X509::Certificate]
        peer_certificates = []
        @peer_certificates = peer_certificates
        # @type var exporter_values: Hash[String, String]
        exporter_values = {}
        @exporter_values = exporter_values
        start_key_updates
      end

      # The ClientHello comes in as a message; there is nothing to send first.
      def start(now:) = nil

      def expected_types(state, epoch)
        return NONE if state.nil?
        types = EXPECTED.fetch(state).fetch(epoch, NONE)
        @config.profile.allow_key_update_message ? types : types - [KeyUpdate::MSG_TYPE]
      end

      def unexpected_reason(state, msg_type) = :unexpected_message

      def handle(message, raw:, transcript_hash_before:, now:)
        case message
        when ClientHello then client_hello(message, now)
        when Certificate then certificate(message, now)
        when CertificateVerify then certificate_verify(message, transcript_hash_before) # steep:ignore
        when Finished then finished(message, transcript_hash_before, now) # steep:ignore
        when KeyUpdate then receive_key_update(message)
        end
      end

      def forget_secrets!
        @exporter_values.each_value(&:clear).clear
        nil
      end

      private def key_schedule = @conductor.key_schedule || raise("the key schedule has not started")

      private def suite = @cipher_suite || raise("no cipher suite was negotiated")

      private def own_side = :server

      private def peer_side = :client

      private def fail!(alert, reason) = @conductor.fail!(alert, reason)

      private def client_hello(ch, now)
        first = @client_hello
        if first
          failure = check_second_client_hello(first, ch)
          return fail!(failure.alert, failure.reason) if failure
        end
        profile = @config.profile
        types = ch.extensions.map(&:extension_type)
        # 1, 2: RFC 9001 "QUIC Transport Parameters Extension", both ways.
        return fail!(:missing_extension, :required_extension) unless (profile.required_extensions - types).empty?
        return fail!(:unsupported_extension, :forbidden_extension) unless (types & profile.forbidden_extensions).empty?
        # 3: RFC 9001 "Prohibit TLS Middlebox Compatibility Mode".
        if profile.reject_nonempty_session_id && !ch.legacy_session_id.empty?
          return fail!(:illegal_parameter, :nonempty_legacy_session_id)
        end
        # 4
        @server_name = server_name(ch)
        return fail!(:missing_extension, :server_name) if @config.require_server_name && @server_name.nil?
        # 5: our order; a suite the Profile never selects is passed over, not
        # refused.
        suite = @config.cipher_suite_ids.filter_map { |id| CipherSuite.find(id) }.find do |candidate|
          ch.cipher_suites.include?(candidate.id) && !profile.never_select_cipher_suites.include?(candidate.name)
        end
        return fail!(:handshake_failure, :no_common_cipher_suite) unless suite
        # 6
        groups = case (ext = ch.extension(Extension::SupportedGroups::TYPE))
          when Extension::SupportedGroups then ext.named_group_list
          end
        if ch.extension(Extension::PreSharedKey::TYPE) && !psk_dhe_ke?(ch) && groups.nil?
          return fail!(:insufficient_security, :psk_dhe_ke_not_offered)
        end
        # 7: a mutual group the client sent a share for saves a round trip;
        # otherwise our first mutual group, by HelloRetryRequest.
        # @type var shares: Array[Extension::KeyShare::Entry]
        shares = case (ext = ch.extension(Extension::KeyShare::TYPE))
          when Extension::KeyShare::CH then ext.client_shares
          else []
          end
        mutual = @config.group_ids & (groups || [])
        group = mutual.find { |id| shares.any? { |share| share.group == id } } || mutual.first
        return fail!(:handshake_failure, :no_common_group) unless group
        # 8, 9
        offered_alpn = case (ext = ch.extension(Extension::Alpn::TYPE))
          when Extension::Alpn then ext.protocol_name_list
          end
        alpn = offered_alpn && @config.alpn.find { |protocol| offered_alpn.include?(protocol) }
        if offered_alpn && !@config.alpn.empty? && alpn.nil?
          return fail!(:no_application_protocol, :no_common_application_protocol)
        end
        return fail!(:no_application_protocol, :application_protocol_required) if profile.require_alpn && alpn.nil?
        # 10
        group_name = IANA::NAMED_GROUPS.fetch(group)
        share = shares.find { |entry| entry.group == group }
        unless share
          return fail!(:illegal_parameter, :missing_key_share) if first
          return hello_retry_request(ch, suite, group)
        end
        encapsulated = @keyring.key_exchange.encapsulate(group_name, share.key_exchange)
        return fail!(:illegal_parameter, :invalid_key_share) unless encapsulated
        ciphertext, shared_secret = encapsulated
        # The PSK, then 11; a certificate only without one.
        case (resumption = choose_psk(ch, suite, alpn, now))
        when Violation
          shared_secret.clear
          return fail!(resumption.alert, resumption.reason)
        when Resumption
          selected = nil
        else
          # 12, 13
          algorithms = case (ext = ch.extension(Extension::SignatureAlgorithms::TYPE))
            when Extension::SignatureAlgorithms then ext.supported_signature_algorithms
            end
          return fail!(:missing_extension, :signature_algorithms) unless algorithms
          selected = @keyring.server_credential(server_name: @server_name, signature_algorithms: algorithms,
            signature_algorithms_cert: signature_algorithms_cert(ch), certificate_authorities: certificate_authorities(ch))
          return fail!(:handshake_failure, :no_usable_certificate) unless selected
        end

        @resumption = resumption
        @client_hello = ch
        @cipher_suite = suite
        @group = group_name
        @alpn = alpn
        ch.extensions.each do |ext|
          next if Config::RESERVED_EXTENSIONS.include?(ext.extension_type) || IANA.grease?(ext.extension_type)
          @conductor.event!(Event::PeerExtension.new(type: ext.extension_type, data: ext.encode, message: ClientHello::MSG_TYPE))
        end
        send_first_flight(ch, Extension::KeyShare::Entry.new(group:, key_exchange: ciphertext), shared_secret, selected)
      end

      # The first identity whose ticket opens and passes the checks against
      # the current Config, its binder verified, or nil for a full
      # handshake, with the reason each identity was passed over traced.
      # Only a binder that does not verify fails the handshake (RFC 9846
      # "Pre-Shared Key Extension").
      private def choose_psk(ch, suite, alpn, now)
        offer = case (ext = ch.extension(Extension::PreSharedKey::TYPE))
          when Extension::PreSharedKey::CH then ext
          end
        keys = @config.ticket_keys
        return nil unless offer && keys
        unless psk_dhe_ke?(ch)
          offer.identities.each_index { |index| reject_psk(index, :psk_mode_unsupported) }
          return nil
        end
        binding = Ticket.binding(@config.ticket_binding, resumption_binding: @resumption_binding, server_name: @server_name || "",
          alpn: alpn || "")
        offer.identities.each_with_index do |identity, index|
          case (opened = Ticket.open(identity.identity, keys:, binding:, now:, max_size: @config.max_ticket_size))
          when Ticket::Plaintext
            reason = ticket_refusal(opened, suite, now)
            return verify_binder(index, opened, offer.binders.fetch(index), suite) unless reason
            reject_psk(index, reason)
          else reject_psk(index, opened)
          end
        end
        nil
      end

      # The first check of `ticket` against the current Config at `now` that
      # it fails, nil when it passes them all: the age of the ticket and of
      # the full handshake its key material comes from, the hash of the
      # suite, and whether the client is to be authenticated now as it was
      # then.
      private def ticket_refusal(ticket, suite, now)
        now_ms = (now.to_r * 1000).floor
        lifetime = [ticket.lifetime, @config.ticket_lifetime, Config::MAX_TICKET_LIFETIME].min
        return :ticket_expired if now_ms - ticket.issued_at > lifetime * 1000
        return :authentication_expired if now_ms - ticket.authenticated_at > Config::MAX_TICKET_LIFETIME * 1000
        return :cipher_suite_hash_mismatch unless CipherSuite.find(ticket.cipher_suite)&.hash_algorithm == suite.hash_algorithm
        client = ticket.client
        return :client_certificate_missing if client.nil? && @config.client_auth == :required
        return :client_auth_disabled if client && @config.client_auth == :none
        # Tickets of client certificates wait for the checks that resume them.
        return :client_auth_not_resumable if client
        nil
      end

      # Constant time, a binder of the wrong length not verifying either.
      private def verify_binder(index, ticket, binder, suite)
        schedule = KeySchedule.new(hash: suite.hash_algorithm, psk: ticket.psk)
        verified = schedule.verify_binder(kind: :resumption, transcript_hash: @conductor.binder_transcript_hash(suite.hash_algorithm), binder:)
        schedule.discard!
        return Violation.new(alert: :decrypt_error, reason: :psk_binder_mismatch) unless verified
        @conductor.trace(Trace::BinderVerified.new(index:)) if @conductor.tracing?
        Resumption.new(index:, ticket:)
      end

      private def reject_psk(index, reason)
        @conductor.trace(Trace::PskRejected.new(index:, reason:)) if @conductor.tracing?
        nil
      end

      # 0a to 0c of the state machine's table for the second ClientHello: the
      # first that fails.
      private def check_second_client_hello(first, second)
        same = %i[legacy_version random legacy_session_id cipher_suites legacy_compression_methods].all? do |field|
          first.public_send(field) == second.public_send(field)
        end
        kept = ->(ch) { ch.extensions.reject { |ext| ALLOWED_TO_CHANGE.include?(ext.extension_type) } }
        hrr = @hello_retry_request or raise "a second ClientHello without a HelloRetryRequest"
        sent_cookie = hrr.extension(Extension::Cookie::TYPE)
        cookie = second.extension(Extension::Cookie::TYPE)
        unless same && kept.call(first) == kept.call(second) && cookie&.encode == sent_cookie&.encode
          return Violation.new(alert: :illegal_parameter, reason: :client_hello_changed)
        end
        if second.extension(Extension::EarlyData::TYPE)
          return Violation.new(alert: :illegal_parameter, reason: :early_data_after_hello_retry_request)
        end
        requested = case (ext = hrr.extension(Extension::KeyShare::TYPE))
          when Extension::KeyShare::HRR then ext.selected_group
          end
        # @type var shares: Array[Integer]
        shares = case (ext = second.extension(Extension::KeyShare::TYPE))
          when Extension::KeyShare::CH then ext.client_shares.map(&:group)
          else []
          end
        return Violation.new(alert: :illegal_parameter, reason: :key_share_not_requested_group) if requested && shares != [requested]
        nil
      end

      private def hello_retry_request(ch, suite, group)
        hrr = ServerHello.new(
          legacy_version: ClientHelloBuilder::LEGACY_VERSION, random: ServerHello::HELLO_RETRY_REQUEST_RANDOM,
          legacy_session_id_echo: ch.legacy_session_id, cipher_suite: suite.id, legacy_compression_method: 0,
          extensions: [
            Extension::KeyShare::HRR.new(selected_group: group),
            Extension::SupportedVersions::SH.new(selected_version: ClientHelloBuilder::TLS13)
          ]
        )
        @client_hello = ch
        @cipher_suite = suite
        @hello_retry_request = @conductor.emit_hello_retry_request!(hrr, suite.hash_algorithm)
        @conductor.transition!(:wait_ch2)
      end

      # A server that resumes authenticates by the PSK alone, sending
      # neither a certificate nor a CertificateRequest (RFC 9846
      # "Certificate Request"); otherwise `selected` is the credential and
      # scheme to sign with.
      private def send_first_flight(ch, share, shared_secret, selected)
        suite = self.suite
        resumption = @resumption
        extensions = [
          Extension::KeyShare::SH.new(server_share: share),
          Extension::SupportedVersions::SH.new(selected_version: ClientHelloBuilder::TLS13)
        ] #: Array[Extension::_Extension]
        extensions << Extension::PreSharedKey::SH.new(selected_identity: resumption.index) if resumption
        server_hello = ServerHello.new(
          legacy_version: ClientHelloBuilder::LEGACY_VERSION, random: @keyring.random_bytes(32),
          legacy_session_id_echo: ch.legacy_session_id, cipher_suite: suite.id, legacy_compression_method: 0, extensions:
        )
        @conductor.emit_server_hello!(server_hello, suite.hash_algorithm)
        @authenticated_at = resumption.ticket.authenticated_at if resumption
        schedule = @conductor.start_key_schedule(hash: suite.hash_algorithm, client_random: ch.random, psk: resumption&.ticket&.psk)
        schedule.handshake!(shared_secret)
        shared_secret.clear
        transcript_hash = @conductor.transcript_hash
        client_handshake = schedule.client_handshake_traffic_secret(transcript_hash)
        server_handshake = schedule.server_handshake_traffic_secret(transcript_hash)

        @conductor.emit_message!(:handshake, EncryptedExtensions.new(extensions: encrypted_extensions(ch)))
        if selected
          credential, scheme = selected
          @conductor.emit_message!(:handshake, certificate_request) unless @config.client_auth == :none
          @conductor.emit_message!(:handshake, @authentication.certificate(credential))
          @conductor.emit_message!(:handshake, @authentication.certificate_verify(credential, scheme, @conductor.transcript_hash))
        end
        @conductor.emit_message!(:handshake, @authentication.finished(schedule, @conductor.transcript_hash))

        schedule.main!
        through_server_finished = @conductor.transcript_hash
        server_application = schedule.server_application_traffic_secret(through_server_finished)
        schedule.client_application_traffic_secret(through_server_finished)
        @exporter_values = schedule.exporter_values(@config.exporter_labels, through_server_finished)
        moved = @conductor.change_epochs!(cipher_suite: suite, read: :handshake, write: :application, secrets: [
          [:handshake, :read, client_handshake], [:handshake, :write, server_handshake],
          [:application, :write, server_application]
        ])
        @conductor.transition!(resumption || @config.client_auth == :none ? :wait_finished : :wait_cert) if moved
      end

      # The client offered every type we answer with: server_name when its
      # SNI was used, ALPN, record_size_limit, and the extensions given from
      # outside. A given extension of a type the client did not offer is
      # dropped, as a server may not send it, and traced so the mistake shows.
      private def encrypted_extensions(ch)
        offered = ch.extensions.map(&:extension_type)
        # @type var extensions: Array[Extension::_Extension]
        extensions = []
        extensions << Extension::ServerName::EE.new if @server_name
        alpn = @alpn
        extensions << Extension::Alpn.new(protocol_name_list: [alpn]) if alpn
        case (ext = ch.extension(Extension::RecordSizeLimit::TYPE))
        when Extension::RecordSizeLimit then @peer_record_size_limit = ext.record_size_limit
        end
        limit = @config.record_size_limit
        if limit && offered.include?(Extension::RecordSizeLimit::TYPE)
          extensions << Extension::RecordSizeLimit.new(record_size_limit: limit)
        end
        (@config.extensions + @extensions).each do |ext|
          if offered.include?(ext.extension_type)
            extensions << ext
          elsif @conductor.tracing?
            @conductor.trace(Trace::ExtensionDropped.new(type: ext.extension_type))
          end
        end
        extensions
      end

      # RFC 9846 "Certificate Request": an empty context during the
      # handshake, our signature schemes, and the CAs we trust unless the
      # Config says not to name them.
      private def certificate_request
        extensions = [Extension::SignatureAlgorithms.new(supported_signature_algorithms: @config.signature_algorithm_ids)] #: Array[Extension::_Extension]
        unless @config.signature_algorithm_cert_ids == @config.signature_algorithm_ids
          extensions << Extension::SignatureAlgorithmsCert.new(supported_signature_algorithms: @config.signature_algorithm_cert_ids)
        end
        subjects = @keyring.trust_anchor_subjects
        if @config.certificate_authorities && !subjects.empty?
          extensions << Extension::CertificateAuthorities.new(authorities: subjects)
        end
        CertificateRequest.new(certificate_request_context: "".b, extensions:)
      end

      private def certificate(message, now)
        return fail!(:decode_error, :certificate_request_context) unless message.certificate_request_context.empty?
        if message.certificate_list.empty?
          return fail!(:certificate_required, :certificate_required) if @config.client_auth == :required
          # :optional: on without client authentication.
          return @conductor.transition!(:wait_finished)
        end
        return fail!(:unsupported_extension, :unsolicited_extension) if message.certificate_list.any? { |entry| !entry.extensions.empty? }
        result = @authentication.verify_certificate(message, keyring: @keyring, server_name: nil, now:,
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
        result = @authentication.verify_certificate_verify(message, leaf, offered: @config.signature_algorithm_ids, transcript_hash:)
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
        # RFC 9001 "Receiving Out-of-Order Protected Packets": no 1-RTT data
        # from the client before its Finished.
        return unless @conductor.change_epochs!(cipher_suite: suite, read: :application,
          secrets: [[:application, :read, schedule.application_traffic_secret(:client)]])
        schedule.resumption!(@conductor.transcript_hash)
        @conductor.transition!(:connected)
        issue_tickets(schedule, now)
        @conductor.event!(Event::HandshakeComplete.new(
          server_name: @server_name, alpn: @alpn, cipher_suite: suite.name, group: @group, resumed: !@resumption.nil?,
          early_data_accepted: false, peer_certificates: @peer_certificates,
          peer_verified: !@peer_certificates.empty? && @keyring.peer_verified?
        ))
      end

      # Issues ticket_count tickets right after the client Finished, sealed
      # under the key of `now`; none, the reason traced, for a client that
      # does not take psk_dhe_ke, without a key that seals now, for an
      # authenticated client, or past 7 days from the full handshake the
      # key material comes from. A ticket past max_ticket_size is not sent.
      private def issue_tickets(schedule, now)
        return unless @config.issues_tickets?
        keys = @config.ticket_keys or return
        ch = @client_hello or raise "no ClientHello to issue tickets for"
        return refuse_ticket(:psk_mode_unsupported) unless psk_dhe_ke?(ch)
        entry = keys.sealing(now) or return refuse_ticket(:ticket_keys_exhausted)
        # Tickets of client certificates wait for the checks that resume them.
        return refuse_ticket(:client_auth_not_resumable) unless @peer_certificates.empty?
        now_ms = (now.to_r * 1000).floor
        authenticated_at = @authenticated_at ||= now_ms
        return refuse_ticket(:authentication_expired) if now_ms - authenticated_at > Config::MAX_TICKET_LIFETIME * 1000
        binding = Ticket.binding(@config.ticket_binding, resumption_binding: @resumption_binding, server_name: @server_name || "",
          alpn: @alpn || "")
        early_data = @config.max_early_data_size
        extensions = early_data.positive? ? [Extension::EarlyData::NST.new(max_early_data_size: early_data)] : [] #: Array[Extension::_Extension]
        @config.ticket_count.times do |index|
          nonce = [index].pack("Q>")
          age_add = @keyring.random_bytes(4).unpack1("N") #: Integer
          psk = schedule.ticket_psk(nonce)
          plaintext = Ticket::Plaintext.new(issued_at: now_ms, authenticated_at:, lifetime: @config.ticket_lifetime,
            age_add:, cipher_suite: suite.id, psk:, alpn: @alpn || "".b, early_data_allowed: early_data.positive?, client: nil,
            early_data_context: @early_data_context)
          ticket = Ticket.seal(plaintext, entry:, binding:, random: @keyring.random_bytes(Ticket::RANDOM_LENGTH))
          psk.clear
          next refuse_ticket(:ticket_too_large) if ticket.bytesize > @config.max_ticket_size
          @conductor.emit_message!(:application, NewSessionTicket.new(ticket_lifetime: @config.ticket_lifetime, ticket_age_add: age_add,
            ticket_nonce: nonce, ticket:, extensions:))
        end
      end

      private def refuse_ticket(reason)
        @conductor.trace(Trace::TicketNotIssued.new(reason:)) if @conductor.tracing?
        nil
      end

      private def server_name(ch)
        case (ext = ch.extension(Extension::ServerName::TYPE))
        when Extension::ServerName::CH
          host_name = ext.host_name or return nil
          name, ignored = ServerName.for_server(host_name)
          @conductor.trace(Trace::ServerNameIgnored.new(reason: ignored)) if ignored && @conductor.tracing?
          name
        end
      end

      private def psk_dhe_ke?(ch)
        case (ext = ch.extension(Extension::PskKeyExchangeModes::TYPE))
        when Extension::PskKeyExchangeModes then ext.ke_modes.include?(PSK_DHE_KE)
        else false
        end
      end

      private def signature_algorithms_cert(ch)
        case (ext = ch.extension(Extension::SignatureAlgorithmsCert::TYPE))
        when Extension::SignatureAlgorithmsCert then ext.supported_signature_algorithms
        end
      end

      private def certificate_authorities(ch)
        case (ext = ch.extension(Extension::CertificateAuthorities::TYPE))
        when Extension::CertificateAuthorities then ext.authorities
        end
      end
    end
  end
end
