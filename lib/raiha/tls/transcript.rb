# frozen_string_literal: true

require_relative "crypto"
require_relative "error"

module Raiha::Next::TLS
  # The running transcript hash (RFC 9846 "Transcript Hash").
  #
  # It takes handshake messages as the bytes that went over the wire, header
  # included, and never re-encoded values. A client does not know the cipher
  # suite until the ServerHello, so it runs up to two hashes until `#select!`.
  #
  # There is no snapshot API: the state machine takes the digest right
  # before or after adding a message, and derives the resumption secret at
  # the client Finished instead of keeping a copy. A PSK binder is expressed
  # by order alone: add the ClientHello up to the binders, take the digest,
  # then add the rest.
  class Transcript
    # The handshake messages that enter the transcript: ClientHello,
    # ServerHello (and HelloRetryRequest), EndOfEarlyData, EncryptedExtensions,
    # Certificate, CertificateRequest, CertificateVerify, Finished,
    # CompressedCertificate and the synthetic message_hash. NewSessionTicket
    # and KeyUpdate never do.
    TRANSCRIPT_MESSAGES = Set[1, 2, 5, 8, 11, 13, 15, 20, 25, 254].freeze

    MESSAGE_HASH = 254

    def initialize(hashes:)
      if hashes.empty? || hashes.size > 2 || hashes.uniq.size != hashes.size
        raise ArgumentError, "a transcript runs one or two distinct hashes: #{hashes.inspect}"
      end
      @digests = hashes.to_h { |hash| [hash, Crypto::Digest.new(hash)] }
      @selected = nil #: Symbol?
      @header = "".b
      @length = 0
      @restarted = false
    end

    def selected = @selected

    def <<(bytes)
      @header << bytes.byteslice(0, 4 - @header.bytesize) if @header.bytesize < 4 # steep:ignore
      @length += bytes.bytesize
      @digests.each_value { |digest| digest << bytes }
      self
    end

    # The hash of everything added so far, with the selected hash unless one
    # is named.
    def digest(hash = @selected)
      raise UsageError, "no hash is selected yet; name one" if hash.nil?
      running(hash).digest
    end

    # Keeps only `hash` once the cipher suite is known.
    def select!(hash)
      digest = running(hash)
      raise UsageError, "#{@selected.inspect} is already selected" if @selected && @selected != hash
      @digests = { hash => digest }
      @selected = hash
      self
    end

    # Replaces ClientHello1 with message_hash(Hash(ClientHello1)) after a
    # HelloRetryRequest. Call it after `#select!` with the hash of the
    # HelloRetryRequest's suite, when the transcript holds exactly
    # ClientHello1, right before adding the HelloRetryRequest. A stateless
    # server passes the ClientHello1 hash it kept in the cookie as `digest:`.
    def restart_with_message_hash!(digest: nil)
      hash = @selected or raise UsageError, "select! the negotiated hash before restarting"
      raise UsageError, "the transcript has already been restarted" if @restarted
      unless only_client_hello?
        raise UsageError, "restart_with_message_hash! needs a transcript of exactly ClientHello1"
      end
      client_hello_hash = digest || self.digest(hash)
      restarted = Crypto::Digest.new(hash)
      restarted << [MESSAGE_HASH, 0, 0, client_hello_hash.bytesize].pack("C4") << client_hello_hash
      @digests = { hash => restarted }
      @restarted = true
      self
    end

    private def running(hash)
      @digests.fetch(hash) { raise UsageError, "#{hash.inspect} is not running in this transcript" }
    end

    private def only_client_hello?
      return false unless @header.bytesize == 4 && @header.getbyte(0) == 1
      # The 4-byte header is complete, so every getbyte below is in range.
      length = (@header.getbyte(1) << 16) | (@header.getbyte(2) << 8) | @header.getbyte(3) # steep:ignore
      @length == 4 + length
    end
  end
end
