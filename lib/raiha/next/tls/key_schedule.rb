# frozen_string_literal: true

require_relative "codec"
require_relative "crypto"

module Raiha::Next::TLS
  # The derivation functions of the TLS 1.3 key schedule (RFC 9846 "Key
  # Schedule"). They are public because QUIC derives its packet protection
  # keys from TLS traffic secrets with labels of its own ("quic key", ...),
  # so this layer hands out secrets and the functions, never derived keys.
  module KeySchedule
    PREFIX = "tls13 "

    # Every label the TLS key schedule uses, written here and nowhere else.
    # RFC 9846 renamed "master" to "main" but kept the labels, so a name here
    # does not have to match its label.
    LABELS = {
      derived: "derived",
      external_binder: "ext binder",
      resumption_binder: "res binder",
      client_early_traffic: "c e traffic",
      early_exporter: "e exp master",
      client_handshake_traffic: "c hs traffic",
      server_handshake_traffic: "s hs traffic",
      client_application_traffic: "c ap traffic",
      server_application_traffic: "s ap traffic",
      exporter: "exp master",
      resumption: "res master",
      ticket_psk: "resumption",
      exporter_value: "exporter",
      finished: "finished",
      key: "key",
      iv: "iv",
      traffic_update: "traffic upd"
    }.freeze #: Hash[Symbol, String]

    def self.extract(salt:, ikm:, hash:) = Crypto::HKDF.extract(hash:, salt:, ikm:)

    # HKDF-Expand-Label. `label` is given without the "tls13 " prefix.
    def self.expand_label(secret:, label:, length:, hash:, context: "".b)
      w = Codec::Writer.new
      w.u16(length)
      w.vector(1, min: 7, max: 255) { w.bytes(PREFIX + label) }
      w.vector(1, max: 255) { w.bytes(context) }
      Crypto::HKDF.expand(hash:, prk: secret, info: w.to_s, length:)
    end

    def self.derive_secret(secret:, label:, transcript_hash:, hash:)
      expand_label(secret:, label:, context: transcript_hash, length: Crypto.hash_length(hash), hash:)
    end
  end
end
