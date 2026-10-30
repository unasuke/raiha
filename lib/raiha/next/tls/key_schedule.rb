# frozen_string_literal: true

require_relative "codec"
require_relative "crypto"
require_relative "error"

module Raiha::Next::TLS
  # The TLS 1.3 key schedule (RFC 9846 "Key Schedule").
  #
  # The class methods are the derivation functions. They are public because
  # QUIC derives its packet protection keys from TLS traffic secrets with
  # labels of its own ("quic key", ...), so this layer hands out secrets and
  # the functions, never derived keys.
  #
  # An instance walks one handshake through the stages early, handshake,
  # main and resumption, holding the current stage's secret and forgetting
  # the previous one on each step, as RFC 9846 asks of secrets whose
  # derivations are done. It also keeps the secrets still needed after they
  # are handed out: the finished keys until used, and the current
  # application traffic secrets for KeyUpdate. A call out of order, or one
  # that needs a forgotten secret, raises UsageError.
  #
  # Forgetting is String#clear, a best effort: Ruby's GC may have copied a
  # secret before it was cleared.
  class KeySchedule
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

    BINDER_LABELS = { external: :external_binder, resumption: :resumption_binder }.freeze #: Hash[Symbol, Symbol]

    def self.extract(salt:, ikm:, hash:) = Crypto::HKDF.extract(hash:, salt:, ikm:)

    # HKDF-Expand-Label. `label` is given without the "tls13 " prefix; a
    # derivation of this implementation's own gives a prefix of its own.
    def self.expand_label(secret:, label:, length:, hash:, context: "".b, prefix: PREFIX)
      w = Codec::Writer.new
      w.u16(length)
      w.vector(1, min: 7, max: 255) { w.bytes(prefix + label) }
      w.vector(1, max: 255) { w.bytes(context) }
      Crypto::HKDF.expand(hash:, prk: secret, info: w.to_s, length:)
    end

    def self.derive_secret(secret:, label:, transcript_hash:, hash:)
      expand_label(secret:, label:, context: transcript_hash, length: Crypto.hash_length(hash), hash:)
    end

    # The outer step of TLS-Exporter, from the inner value `#exporter_values`
    # computed for the label (RFC 9846 "Exporters"). A missing context and an
    # empty one give the same value.
    def self.export(inner_value:, context:, length:, hash:)
      expand_label(secret: inner_value, label: LABELS.fetch(:exporter_value), context: Crypto.hash(hash, context), length:, hash:)
    end

    attr_reader :hash_algorithm, :stage

    # The early secret from `psk`, or from zeros without one. The hash is
    # fixed here: a server knows it once the suite and PSK are chosen, a
    # client from the PSK it offers or the ServerHello. `on_traffic_secret`
    # is called with the name of each traffic secret and the secret as it
    # is derived, for the keylog; a KeyUpdate's next generation is not.
    def initialize(hash:, psk: nil, on_traffic_secret: nil)
      @on_traffic_secret = on_traffic_secret
      @hash_algorithm = hash
      @hash_length = Crypto.hash_length(hash)
      @empty_hash = Crypto.hash(hash, "".b)
      zeros = "\x00".b * @hash_length
      @secret = KeySchedule.extract(salt: zeros, ikm: psk || zeros, hash:)
      @stage = :early
      # @type var finished_keys: Hash[side, String]
      finished_keys = {}
      @finished_keys = finished_keys
      # @type var application_traffic_secrets: Hash[side, String]
      application_traffic_secrets = {}
      @application_traffic_secrets = application_traffic_secrets
    end

    # The PSK binder over `transcript_hash`, the hash of the ClientHello up
    # to the binders. `kind` is :external or :resumption.
    def binder(kind:, transcript_hash:)
      binder_key = derive(stage_secret(:early), BINDER_LABELS.fetch(kind), @empty_hash)
      finished_key = expand(binder_key, :finished, @hash_length)
      mac(finished_key, transcript_hash)
    ensure
      binder_key&.clear
      finished_key&.clear
    end

    # Compares in constant time. A binder of the wrong length does not
    # match.
    def verify_binder(kind:, transcript_hash:, binder:)
      expected = binder(kind:, transcript_hash:)
      expected.bytesize == binder.bytesize && Crypto.fixed_length_secure_compare(expected, binder)
    ensure
      expected&.clear
    end

    def client_early_traffic_secret(transcript_hash) = derive_traffic_secret(:client_early_traffic, stage_secret(:early), transcript_hash)

    # To the handshake secret; forgets the early secret.
    def handshake!(shared_secret)
      advance(:early, :handshake) { |early| next_stage(early, shared_secret) }
    end

    # Also makes the client's finished key, kept until used.
    def client_handshake_traffic_secret(transcript_hash) = handshake_traffic_secret(:client, transcript_hash)

    def server_handshake_traffic_secret(transcript_hash) = handshake_traffic_secret(:server, transcript_hash)

    # To the main secret; forgets the handshake secret.
    def main!
      advance(:handshake, :main) { |handshake| next_stage(handshake, "\x00".b * @hash_length) }
    end

    def client_application_traffic_secret(transcript_hash) = derive_application_traffic_secret(:client, transcript_hash)

    def server_application_traffic_secret(transcript_hash) = derive_application_traffic_secret(:server, transcript_hash)

    # A copy of `side`'s current application traffic secret: a server
    # derives the client's at its own Finished and hands it out only once the
    # client's Finished verifies.
    def application_traffic_secret(side)
      current = @application_traffic_secrets[side] or raise UsageError, "no #{side} application traffic secret yet"
      current.dup
    end

    # The inner exporter value of each label, Derive-Secret(exporter_secret,
    # label, ""), from which `KeySchedule.export` makes any length. The
    # exporter secret itself is never returned and is forgotten at once; with
    # no labels it is not derived at all.
    def exporter_values(labels, transcript_hash)
      main = stage_secret(:main)
      return {} if labels.empty?
      exporter_secret = derive(main, :exporter, transcript_hash)
      labels.to_h do |label|
        [label, KeySchedule.derive_secret(secret: exporter_secret, label:, transcript_hash: @empty_hash, hash: @hash_algorithm)]
      end
    ensure
      exporter_secret&.clear
    end

    # The verify_data of our own Finished. Uses up that side's finished key.
    def finished_verify_data(side, transcript_hash)
      finished_key = @finished_keys.delete(side) or raise UsageError, "no #{side} finished key: derive it first, and use it once"
      mac(finished_key, transcript_hash)
    ensure
      finished_key&.clear
    end

    # Whether the peer's verify_data matches, compared in constant time; one
    # of the wrong length does not. Uses up that side's finished key.
    def verify_finished(side, transcript_hash, verify_data)
      expected = finished_verify_data(side, transcript_hash)
      expected.bytesize == verify_data.bytesize && Crypto.fixed_length_secure_compare(expected, verify_data)
    ensure
      expected&.clear
    end

    # To the resumption secret; forgets the main secret. The transcript runs
    # through the client Finished.
    def resumption!(transcript_hash)
      advance(:main, :resumption) { |main| derive(main, :resumption, transcript_hash) }
    end

    # The PSK of the ticket that carries `ticket_nonce`.
    def ticket_psk(ticket_nonce)
      KeySchedule.expand_label(secret: stage_secret(:resumption), label: LABELS.fetch(:ticket_psk), context: ticket_nonce,
        length: @hash_length, hash: @hash_algorithm)
    end

    # The next generation of `side`'s application traffic secret, for a TLS
    # KeyUpdate; forgets the current one.
    def update_application_traffic_secret!(side)
      current = @application_traffic_secrets[side] or raise UsageError, "no #{side} application traffic secret yet"
      updated = expand(current, :traffic_update, @hash_length)
      current.clear
      @application_traffic_secrets[side] = updated
      updated.dup
    end

    # Forgets every secret. Nothing can be derived afterwards.
    def discard!
      @secret.clear
      @finished_keys.each_value(&:clear).clear
      @application_traffic_secrets.each_value(&:clear).clear
      @stage = :discarded
      self
    end

    private def instance_variables_to_inspect = %i[@hash_algorithm @stage]

    private def handshake_traffic_secret(side, transcript_hash)
      label = side == :client ? :client_handshake_traffic : :server_handshake_traffic
      traffic_secret = derive_traffic_secret(label, stage_secret(:handshake), transcript_hash)
      @finished_keys[side]&.clear
      @finished_keys[side] = expand(traffic_secret, :finished, @hash_length)
      traffic_secret
    end

    # Keeps the secret for KeyUpdate and returns a copy, since the copy
    # handed out cannot be cleared from here.
    private def derive_application_traffic_secret(side, transcript_hash)
      label = side == :client ? :client_application_traffic : :server_application_traffic
      traffic_secret = derive_traffic_secret(label, stage_secret(:main), transcript_hash)
      @application_traffic_secrets[side]&.clear
      @application_traffic_secrets[side] = traffic_secret
      traffic_secret.dup
    end

    private def advance(from, to)
      previous = stage_secret(from)
      @secret = yield(previous)
      previous.clear
      @stage = to
      self
    end

    # The Extract of the next stage, salted with Derive-Secret(., "derived", "").
    private def next_stage(secret, ikm)
      salt = derive(secret, :derived, @empty_hash)
      KeySchedule.extract(salt:, ikm:, hash: @hash_algorithm)
    ensure
      salt&.clear
    end

    private def stage_secret(stage)
      raise UsageError, "the key schedule is at #{@stage}, not #{stage}" unless @stage == stage
      @secret
    end

    private def derive_traffic_secret(label, secret, transcript_hash)
      derive(secret, label, transcript_hash).tap { |derived| @on_traffic_secret&.call(label, derived) }
    end

    private def derive(secret, label, transcript_hash)
      KeySchedule.derive_secret(secret:, label: LABELS.fetch(label), transcript_hash:, hash: @hash_algorithm)
    end

    private def expand(secret, label, length)
      KeySchedule.expand_label(secret:, label: LABELS.fetch(label), length:, hash: @hash_algorithm)
    end

    private def mac(key, data) = Crypto.hmac(hash: @hash_algorithm, key:, data:)
  end
end
