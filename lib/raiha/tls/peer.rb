# frozen_string_literal: true

require_relative "../crypto_util"

module Raiha
  module TLS
    # Shared behavior between TLS::Client and TLS::Server.
    class Peer
      # RFC 8446 Section 7.1: derive client/server application traffic secrets
      # from the current master secret and transcript hash.
      private def derive_application_traffic_secrets
        @key_schedule.derive_client_application_traffic_secret(@transcript_hash.hash)
        @key_schedule.derive_server_application_traffic_secret(@transcript_hash.hash)
      end

      # RFC 8446 Section 4.2.11.2: compute the PSK binder over a truncated
      # ClientHello. Both sides run the exact same computation (client to
      # populate the binder, server to verify it).
      private def compute_psk_binder(psk, truncated_client_hello, hash_alg)
        digest_length = OpenSSL::Digest.new(hash_alg).digest_length

        early_secret = OpenSSL::HMAC.digest(hash_alg, "\x00" * digest_length, psk)
        empty_hash = OpenSSL::Digest.new(hash_alg).digest
        binder_key = CryptoUtil.hkdf_expand_label(early_secret, "res binder", empty_hash, digest_length, hash: hash_alg)
        finished_key = CryptoUtil.hkdf_expand_label(binder_key, "finished", "", digest_length, hash: hash_alg)

        transcript_hash = OpenSSL::Digest.new(hash_alg).digest(truncated_client_hello)
        OpenSSL::HMAC.digest(hash_alg, finished_key, transcript_hash)
      end
    end
  end
end
