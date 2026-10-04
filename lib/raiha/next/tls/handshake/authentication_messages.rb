# frozen_string_literal: true

require_relative "../crypto"
require_relative "../error"
require_relative "../signature_scheme"
require_relative "../trace"
require_relative "../verifier"
require_relative "certificate"
require_relative "certificate_verify"
require_relative "finished"

module Raiha::Next::TLS
  module Handshake
    # Certificate, CertificateVerify and Finished, which RFC 9846 groups as
    # the "Authentication Messages": verifying the peer's and building our
    # own. Both roles use the same steps; what differs between them is the
    # value of Parameters, never a branch on the role.
    #
    # Results come back as return values, never through callbacks: a verified
    # value or a Failure, and messages to send. The caller adds messages to
    # the transcript and the output queue. Transcript hashes come in as
    # arguments, since RFC 9846 signs and MACs a transcript that ends before
    # the message itself.
    #
    # The Trace values that tell a test oracle a check passed are built here,
    # right where it passes, and nowhere else.
    class AuthenticationMessages
      SERVER_CONTEXT = "TLS 1.3, server CertificateVerify"
      CLIENT_CONTEXT = "TLS 1.3, client CertificateVerify"

      # The differences between the roles. The context strings and finished
      # keys swap between verifying the peer and authenticating ourselves, so
      # one value holds both sides to keep them from being mixed up.
      class Parameters < Data.define(:own_side, :peer_side, :own_context, :peer_context)
        CLIENT = new(own_side: :client, peer_side: :server, own_context: CLIENT_CONTEXT, peer_context: SERVER_CONTEXT)
        SERVER = new(own_side: :server, peer_side: :client, own_context: SERVER_CONTEXT, peer_context: CLIENT_CONTEXT)
      end

      # A check that failed: the alert to send and a Symbol naming it.
      class Failure < Data.define(:alert, :reason)
      end

      attr_reader :parameters

      def initialize(parameters, tracer:)
        @parameters = parameters
        @tracer = tracer
      end

      # The peer's chain once the Verifier accepts it, leaf first, or a
      # Failure. An empty certificate_list is the caller's to handle first,
      # as the roles treat it differently.
      def verify_certificate(certificate, keyring:, server_name:, now:, max_chain_length:, context:)
        unless certificate.certificate_request_context == context
          return Failure.new(alert: :decode_error, reason: :certificate_request_context)
        end
        entries = certificate.certificate_list
        return Failure.new(alert: :decode_error, reason: :certificate_chain_too_long) if entries.size > max_chain_length
        # @type var chain: Array[OpenSSL::X509::Certificate]
        chain = []
        entries.each do |entry|
          parsed = Crypto::Certificate.parse(entry.cert_data) or return Failure.new(alert: :bad_certificate, reason: :malformed_certificate)
          chain << parsed
        end
        purpose = @parameters.peer_side
        result = keyring.verifier.verify(chain:, server_name:, now:, purpose:)
        raise UsageError, "a Verifier must return a Verifier::Result, not #{result.class}" unless result.is_a?(Verifier::Result)
        return Failure.new(alert: result.reason || :bad_certificate, reason: :certificate_rejected) unless result.ok
        @tracer&.tls_trace(Trace::PeerCertificateVerified.new(purpose:))
        result.verified_chain
      end

      # True once the signature verifies, or a Failure. `offered` are the
      # schemes we sent, in signature_algorithms or the CertificateRequest.
      def verify_certificate_verify(certificate_verify, leaf, offered:, transcript_hash:)
        algorithm = certificate_verify.algorithm
        scheme = SignatureScheme.find(algorithm)
        public_key = leaf.public_key
        unless scheme && offered.include?(algorithm) && scheme.usable_in_certificate_verify? &&
            Crypto::Signature.key_matches?(scheme, public_key)
          return Failure.new(alert: :illegal_parameter, reason: :signature_algorithm)
        end
        content = signed_content(@parameters.peer_context, transcript_hash)
        unless Crypto::Signature.verify(scheme, public_key, certificate_verify.signature, content)
          return Failure.new(alert: :decrypt_error, reason: :bad_signature)
        end
        @tracer&.tls_trace(Trace::PeerSignatureVerified.new(algorithm: scheme.name))
        true
      end

      # True once the peer's verify_data matches, or a Failure. A
      # verify_data of the wrong length does not match.
      def verify_finished(finished, key_schedule, transcript_hash)
        unless key_schedule.verify_finished(@parameters.peer_side, transcript_hash, finished.verify_data)
          return Failure.new(alert: :decrypt_error, reason: :bad_finished)
        end
        @tracer&.tls_trace(Trace::PeerFinishedVerified.new(transcript_hash:))
        true
      end

      # Our Certificate; an empty one without a credential, which a client
      # sends when it has nothing to answer a CertificateRequest with.
      def certificate(credential, context: "".b)
        # @type var entries: Array[CertificateEntry]
        entries = []
        credential&.chain_der&.each { |der| entries << CertificateEntry.new(cert_data: der, extensions: []) }
        Certificate.new(certificate_request_context: context, certificate_list: entries)
      end

      def certificate_verify(credential, scheme, transcript_hash)
        content = signed_content(@parameters.own_context, transcript_hash)
        CertificateVerify.new(algorithm: scheme.id, signature: Crypto::Signature.sign(scheme, credential.key, content))
      end

      def finished(key_schedule, transcript_hash)
        Finished.new(verify_data: key_schedule.finished_verify_data(@parameters.own_side, transcript_hash))
      end

      # RFC 9846 "Certificate Verify": 64 spaces, the context string, a zero
      # byte and the transcript hash.
      private def signed_content(context, transcript_hash) = (" " * 64 + context + "\x00").b + transcript_hash
    end
  end
end
