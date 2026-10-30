# frozen_string_literal: true

require_relative "cipher_suite"
require_relative "key_schedule"
require_relative "masked_inspect"

module Raiha::Next::TLS
  # A session a client may resume, as a value: what a NewSessionTicket gave
  # and what of the connection it came on a resumption needs (TLS API
  # design 13.1). The application keeps it where it likes, `to_h` and
  # `from_h` turning it into plain values and back.
  #
  # `issued_at` is when the client received the ticket and
  # `authenticated_at` when the full handshake the session comes from took
  # place, both in milliseconds of the wall clock; `cipher_suite` is the ID
  # of the cipher suite; `peer_certificates` is the server's chain, DER,
  # leaf first; `server_name` and `alpn` are nil for none.
  class Session < Data.define(
    :ticket, :ticket_nonce, :resumption_secret, :cipher_suite,
    :issued_at, :lifetime, :age_add, :max_early_data_size,
    :server_name, :alpn, :peer_certificates, :authenticated_at
  )
    include MaskedInspect

    # RFC 9846 "New Session Ticket Message": no ticket is used more than
    # 7 days after it was issued, and here no key material more than 7
    # days after the full handshake it comes from.
    MAX_AGE = 604_800

    def masked_members = %i[resumption_secret]

    def self.from_h(hash)
      raise ArgumentError, "a session is a Hash" unless hash.is_a?(Hash)
      bytes = ->(name) { hash.fetch(name).then { |v| v.is_a?(String) ? v.b.freeze : raise(ArgumentError, "#{name} must be a String") } }
      integer = ->(name) { hash.fetch(name).then { |v| v.is_a?(Integer) && !v.negative? ? v : raise(ArgumentError, "#{name} must be an Integer") } }
      optional = ->(name) { hash.fetch(name).nil? ? nil : bytes.(name) }
      certificates = hash.fetch(:peer_certificates)
      raise ArgumentError, "peer_certificates must be an Array of Strings" unless certificates.is_a?(Array) && certificates.all?(String)
      raise ArgumentError, "unknown cipher suite" unless CipherSuite.find(integer.(:cipher_suite))
      new(ticket: bytes.(:ticket), ticket_nonce: bytes.(:ticket_nonce), resumption_secret: bytes.(:resumption_secret),
        cipher_suite: integer.(:cipher_suite), issued_at: integer.(:issued_at), lifetime: integer.(:lifetime),
        age_add: integer.(:age_add), max_early_data_size: integer.(:max_early_data_size), server_name: optional.(:server_name),
        alpn: optional.(:alpn), peer_certificates: certificates.map { |der| der.b.freeze }.freeze,
        authenticated_at: integer.(:authenticated_at))
    rescue KeyError => e
      raise ArgumentError, "a session lacks #{e.key}"
    end

    # Whether the session may still be offered at `now`: neither the ticket
    # nor the key material it carries is past its age.
    def usable?(now:)
      now_ms = (now.to_r * 1000).floor
      now_ms - issued_at <= [lifetime, MAX_AGE].min * 1000 && now_ms - authenticated_at <= MAX_AGE * 1000
    end

    # The PSK of the ticket (RFC 9846 "New Session Ticket Message").
    def psk
      suite = CipherSuite.find(cipher_suite) or raise ArgumentError, "unknown cipher suite"
      KeySchedule.expand_label(secret: resumption_secret, label: KeySchedule::LABELS.fetch(:ticket_psk), context: ticket_nonce,
        length: suite.hash_length, hash: suite.hash_algorithm)
    end

    # The obfuscated_ticket_age to offer at `now` (RFC 9846 "Pre-Shared Key
    # Extension"): the milliseconds since the ticket came, plus age_add,
    # modulo 2^32.
    def obfuscated_ticket_age(now) = ((now.to_r * 1000).floor - issued_at + age_add) % (1 << 32)
  end

  module SessionStore
    # Sessions kept in memory by server name, the newest 8 of each. A
    # session is taken out to be offered, as a ticket offered once is not to
    # be offered again (RFC 9846 "Client and Server Tracking Prevention").
    class Memory
      PER_SERVER = 8

      def initialize
        @sessions = {} #: Hash[String?, Array[Session]]
        @lock = Thread::Mutex.new
      end

      def put(session)
        @lock.synchronize do
          kept = @sessions[session.server_name] ||= []
          kept << session
          kept.shift while kept.size > PER_SERVER
        end
        self
      end

      # The newest session for `server_name` still usable at `now`, taken
      # out; sessions past their age are dropped on the way.
      def take(server_name, now:)
        @lock.synchronize do
          kept = @sessions[server_name] or return nil
          while (session = kept.pop)
            return session if session.usable?(now:)
          end
          nil
        end
      end
    end
  end
end
