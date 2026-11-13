# frozen_string_literal: true

module Raiha::Next::QUIC
  module Crypto
    # The Initial keys of both directions (RFC 9001 "Initial Secrets"), from
    # the Destination Connection ID of the client's first Initial packet and
    # the salt of the version. Initial packets always use
    # TLS_AES_128_GCM_SHA256. Whoever sees that packet can derive the same
    # keys, so they keep off-path attackers out and hide nothing.
    class Initial < Data.define(:client, :server)
      SUITE = Raiha::Next::TLS::CipherSuite::TLS_AES_128_GCM_SHA256

      def self.derive(dcid:, version:)
        hash = SUITE.hash_algorithm
        length = SUITE.hash_length
        initial = Raiha::Next::TLS::KeySchedule.extract(salt: version.initial_salt, ikm: dcid, hash:)
        client = Raiha::Next::TLS::KeySchedule.expand_label(secret: initial, label: "client in", length:, hash:)
        server = Raiha::Next::TLS::KeySchedule.expand_label(secret: initial, label: "server in", length:, hash:)
        new(client: Keys.derive(suite: SUITE, secret: client, version:), server: Keys.derive(suite: SUITE, secret: server, version:))
      end
    end
  end
end
