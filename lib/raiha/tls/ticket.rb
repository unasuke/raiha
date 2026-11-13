# frozen_string_literal: true

require_relative "codec"
require_relative "crypto"
require_relative "masked_inspect"
require_relative "profile"
require_relative "ticket_keys"

module Raiha::Next::TLS
  # A session ticket a server seals for itself, holding what a resumption
  # takes from the connection it was issued on:
  #
  #   version (1) || key_id (8) || nonce (12) || AES-256-GCM(padded plaintext) || tag (16)
  #   AAD = version || key_id || binding
  #
  # The binding is a SHA-256 of what must be the same for the ticket to
  # open at all: the format, the Profile, the Config's resumption scope,
  # what the layer above binds it to (the QUIC version), the server name
  # and the ALPN protocol; a ticket of any other fails as a forgery would.
  # The nonce is an HMAC of fresh random bytes, the AAD and the plaintext,
  # so a nonce repeats only with the plaintext, and a predictable random
  # source leaks nothing of the key. The plaintext is padded with zeros to a
  # multiple of 64 bytes, which hides small differences of length.
  module Ticket
    VERSION = 1
    NONCE_LENGTH = 12
    RANDOM_LENGTH = 16
    # The version, the key ID, the nonce and the tag.
    OVERHEAD = 1 + TicketKeys::KEY_ID_LENGTH + NONCE_LENGTH + Crypto::AEAD::TAG_LENGTH
    PADDING = 64
    HASH = :sha256
    PROFILE_NAMES = { Profile::TCP => "tcp", Profile::QUIC => "quic" }.freeze #: Hash[Profile, String]

    # A client certificate as a ticket keeps it: the leaf, the digests of the
    # rules it was verified by and of the anchor its chain ended at (all
    # zeros for a chain that ended at none), when the whole chain was valid
    # (seconds), and whether it was verified.
    class ClientCertificate < Data.define(:leaf, :rules_digest, :anchor_digest, :valid_from, :valid_until, :verified); end

    NO_ANCHOR = ("\x00".b * 32).freeze
    # The latest time a ticket holds, a 64-bit count.
    MAX_TIME = (1 << 64) - 1

    # What a ticket holds. `issued_at` and `authenticated_at` are
    # milliseconds of the wall clock; `client` is nil when the client was not
    # authenticated.
    class Plaintext < Data.define(:issued_at, :authenticated_at, :lifetime, :age_add, :cipher_suite, :psk, :alpn,
      :early_data_allowed, :client, :early_data_context)
      include MaskedInspect

      def masked_members = %i[psk]

      # The encoding, padded with zeros to a multiple of PADDING.
      def encode
        w = Codec::Writer.new
        Ticket.u64(w, issued_at)
        Ticket.u64(w, authenticated_at)
        w.u32(lifetime)
        w.u32(age_add)
        w.u16(cipher_suite)
        w.vector(1, min: 32, max: 64) { w.bytes(psk) }
        w.vector(1, max: 255) { w.bytes(alpn) }
        w.u8(early_data_allowed ? 1 : 0)
        encode_client(w)
        w.vector(2) { w.bytes(early_data_context) }
        bytes = w.to_s
        bytes + ("\x00".b * (-bytes.bytesize % PADDING))
      end

      # The Plaintext of `padded`, nil when it does not parse or its padding
      # is not all zeros. Its PSK is a String of its own, which the server
      # clears once it is done with it.
      def self.decode(padded)
        r = Codec::Reader.new(padded)
        plaintext = new(
          issued_at: Ticket.read_u64(r), authenticated_at: Ticket.read_u64(r), lifetime: r.u32, age_add: r.u32,
          cipher_suite: r.u16, psk: r.opaque(1, min: 32, max: 64).dup, alpn: r.opaque(1, max: 255),
          early_data_allowed: Ticket.read_flag(r), client: decode_client(r), early_data_context: r.opaque(2, max: 0xffff)
        )
        rest = padded.byteslice(padded.bytesize - r.remaining, r.remaining).to_s
        plaintext if rest.count("\x00") == rest.bytesize
      rescue Codec::Malformed
        nil
      end

      def self.decode_client(r)
        return nil unless Ticket.read_flag(r)
        ClientCertificate.new(leaf: r.opaque(3, min: 1, max: 0xffffff), rules_digest: r.bytes(32), anchor_digest: r.bytes(32),
          valid_from: Ticket.read_u64(r), valid_until: Ticket.read_u64(r), verified: Ticket.read_flag(r))
      end

      private def encode_client(w)
        cert = client
        return w.u8(0) unless cert
        w.u8(1)
        w.vector(3, min: 1) { w.bytes(cert.leaf) }
        w.bytes(cert.rules_digest)
        w.bytes(cert.anchor_digest)
        Ticket.u64(w, cert.valid_from)
        Ticket.u64(w, cert.valid_until)
        w.u8(cert.verified ? 1 : 0)
      end
    end

    # The part of the binding a Config gives, computed once for it.
    def self.config_binding(profile:, resumption_scope:)
      w = Codec::Writer.new
      w.u8(VERSION)
      w.vector(1) { w.bytes(PROFILE_NAMES.fetch(profile) { raise ArgumentError, "a ticket binds only the built-in Profiles" }) }
      w.vector(2) { w.bytes(resumption_scope) }
      w.to_s.freeze
    end

    # The binding of a ticket: the Config's part, what the layer above binds
    # it to, the server name ("" for none) and the ALPN protocol ("" for
    # none).
    def self.binding(config_part, resumption_binding:, server_name:, alpn:)
      w = Codec::Writer.new
      w.bytes(config_part)
      w.vector(2) { w.bytes(resumption_binding) }
      w.vector(2) { w.bytes(server_name) }
      w.vector(1) { w.bytes(alpn) }
      Crypto.hash(HASH, w.to_s)
    end

    # The digest of the rules a client certificate is verified by: what the
    # Verifier says they are, given as its resumption_policy, for the
    # client's purpose.
    def self.rules_digest(resumption_policy)
      w = Codec::Writer.new
      w.vector(2) { w.bytes(resumption_policy) }
      w.vector(1) { w.bytes("client") }
      Crypto.hash(HASH, w.to_s)
    end

    # The digest a ticket names the trust anchor `der` by.
    def self.anchor_digest(der) = Crypto.hash(HASH, der)

    # The ticket of `plaintext` under `entry`; `random` is RANDOM_LENGTH fresh
    # bytes.
    def self.seal(plaintext, entry:, binding:, random:)
      padded = plaintext.encode
      header = [VERSION].pack("C") + entry.key_id
      aad = header + binding
      nonce = Crypto.hmac(hash: HASH, key: entry.nonce_key, data: random + aad + padded).byteslice(0, NONCE_LENGTH).to_s
      header + nonce + Crypto::AEAD.new(:aes_256_gcm, entry.aead_key).seal(nonce:, aad:, plaintext: padded)
    end

    # The Plaintext of `ticket`, or why it gives none, cheapest check first:
    # :malformed (a length out of range, or a plaintext that does not parse),
    # :unknown_version, :unknown_key (no key of `keys` opens it at `now`) or
    # :aead_failure (forged, or bound to something else; the two are not told
    # apart).
    def self.open(ticket, keys:, binding:, now:, max_size:)
      return :malformed unless ticket.bytesize.between?(OVERHEAD, max_size)
      return :unknown_version unless ticket.getbyte(0) == VERSION
      header = ticket.byteslice(0, 1 + TicketKeys::KEY_ID_LENGTH).to_s
      entry = keys.opening(header.byteslice(1, TicketKeys::KEY_ID_LENGTH).to_s, now) or return :unknown_key
      nonce = ticket.byteslice(header.bytesize, NONCE_LENGTH).to_s
      sealed = ticket.byteslice(header.bytesize + NONCE_LENGTH, ticket.bytesize).to_s
      padded = Crypto::AEAD.new(:aes_256_gcm, entry.aead_key).open(nonce:, aad: header + binding, ciphertext: sealed)
      return :aead_failure unless padded
      plaintext = Plaintext.decode(padded)
      padded.clear
      plaintext || :malformed #: Plaintext | reason
    end

    def self.u64(w, value)
      raise Codec::EncodeError, "#{value} is out of range 0..2^64-1" unless value.between?(0, (1 << 64) - 1)
      w.u32(value >> 32)
      w.u32(value & 0xffff_ffff)
    end

    def self.read_u64(r) = (r.u32 << 32) | r.u32

    def self.read_flag(r)
      case r.u8
      when 0 then false
      when 1 then true
      else raise Codec::IllegalValue
      end
    end
  end
end
