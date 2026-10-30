# frozen_string_literal: true

module Raiha::Next::TLS
  module Verifier
    # The verifier a Keyring uses unless told otherwise: the chain by RFC 5280
    # through OpenSSL's X509::Store, at the time given, then the server's name
    # by RFC 9525.
    #
    # Revocation is not checked unless `verify_flags` asks for it (for
    # example OpenSSL::X509::V_FLAG_CRL_CHECK, with the CRLs in the store).
    class Default
      # OpenSSL's verification errors, mapped to the alert RFC 9846 has for
      # them; anything else is bad_certificate.
      ALERTS = {
        OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED => :certificate_expired,
        OpenSSL::X509::V_ERR_CERT_REVOKED => :certificate_revoked,
        OpenSSL::X509::V_ERR_UNABLE_TO_GET_ISSUER_CERT => :unknown_ca,
        OpenSSL::X509::V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY => :unknown_ca,
        OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT => :unknown_ca,
        OpenSSL::X509::V_ERR_SELF_SIGNED_CERT_IN_CHAIN => :unknown_ca,
        OpenSSL::X509::V_ERR_INVALID_PURPOSE => :unsupported_certificate
      }.freeze #: Hash[Integer, Symbol]

      # The verify_flags that check revocation.
      REVOCATION_FLAGS = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL

      PURPOSES = {
        server: OpenSSL::X509::PURPOSE_SSL_SERVER,
        client: OpenSSL::X509::PURPOSE_SSL_CLIENT
      }.freeze #: Hash[Symbol, Integer]

      # An X509::Store trusting exactly `trust_anchors`, given as DER.
      def self.store(trust_anchors)
        store = OpenSSL::X509::Store.new
        trust_anchors.each do |der|
          store.add_cert(Crypto::Certificate.parse(der) || raise(ArgumentError, "a trust anchor is not a DER certificate"))
        end
        store
      end

      attr_reader :verify_flags

      def initialize(store:, verify_flags: 0)
        @store = store
        @verify_flags = verify_flags
      end

      def verify(chain:, server_name:, now:, purpose:)
        leaf = chain.first or return failure(:bad_certificate)
        context = OpenSSL::X509::StoreContext.new(@store, leaf, chain.drop(1))
        context.time = now
        context.flags = @verify_flags unless @verify_flags.zero?
        context.purpose = PURPOSES.fetch(purpose)
        return failure(ALERTS.fetch(context.error, :bad_certificate)) unless context.verify # steep:ignore
        if purpose == :server && (server_name.nil? || !HostName.match?(leaf, server_name))
          return failure(:bad_certificate)
        end
        Result.new(ok: true, reason: nil, verified_chain: context.chain || chain)
      rescue OpenSSL::X509::StoreError, OpenSSL::X509::CertificateError
        failure(:bad_certificate)
      end

      def resumption_policy = "default;verify_flags=#{@verify_flags}"

      private def failure(alert) = Result.new(ok: false, reason: alert, verified_chain: [])
    end
  end
end
